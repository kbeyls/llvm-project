//===- bolt/Passes/StackClashAnalysis.cpp ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements a pass that looks for any AArch64 patterns that may
// indicate that a stack can grow larger without at least one memory access
// to every page as the stack grows.
//
//===----------------------------------------------------------------------===//

#include "bolt/Passes/StackClashAnalysis.h"
#include "bolt/Core/ParallelUtilities.h"
#include "bolt/Passes/DataflowAnalysis.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/MC/MCInst.h"
#include "llvm/Support/Format.h"

#define DEBUG_TYPE "bolt-stackclash"

namespace llvm {
namespace bolt {

raw_ostream &operator<<(raw_ostream &OS, const StackClashIssue &G) {
  OS << "stackclash-gadget<>";
  return OS;
}

namespace {

// To be able to compute whether always an access happens on every stack page
// as the stack grows, at least the following (sub-)analyses are needed:
//
// FIXME: update the description below.
// 1. Track which register contain a constant value (as they often are used
//    to adjust the stack pointer).
// 2. Track where the stack pointer gets adjusted to grow the stack, and if
//    it's with a constant amount.
// 3. When the stack grows, track how many pages worth it grows by, which/how
//    many pages remain without an access to it.
// 4. Track which accesses are the first accesses that access such an as-yet
//    not-yet-accessed page.
// Where exactly should an error be reported on? When is the latest time the
// program should have made an access to every newly "allocated" stack page?
// As a first attempt, we could keep it simple and simply demand that all
// newly allocated pages must have been accessed before either
// (a) a next stack growth or shrink happens, or
// (b) the end of the function (this should never happen - if a function grows
//     the stack, it should also shrink the stack, so case (a) should cover all
//     code?)
//
// Step 1 - let's start by implementing detecting an issue on a bare minimal
// example. Therefore, implement (2), (3), (4) and (a).

/// Returns true if the register R is present in the Map M.
bool addToMaxMap(SmallDenseMap<MCPhysReg, uint64_t, 1> &M, MCPhysReg R,
                 const uint64_t MaxValue) {
  auto MIt = M.find(R);
  if (MIt == M.end()) {
    MIt->second = MaxValue;
    return false;
  } else {
    MIt->second = std::max(MIt->second, MaxValue);
    return true;
  }
}

struct State {
  // Store the maximum possible offset to which the stack extends
  // beyond the furthest probe seen.
  MaxOffsetSinceLastProbeT MaxOffsetSinceLastProbe;
  /// ExactValues stores registers that we know have a specific
  /// constant value.
  SmallDenseMap<MCPhysReg, uint64_t, 1> RegConstValues;
  /// RegMaxValues stores registers that we know have a value in the
  /// range [0, MaxValue-1].
  SmallDenseMap<MCPhysReg, uint64_t, 1> RegMaxValues;
  /// Reg2MaxOffset contains the registers that contain the value
  /// of SP at some point during the running function, where it's
  /// guaranteed that at the time the SP value was stored in the register,
  /// a maximum offset for any probe into the stack is a constant.
  /// That constant is stored in this map.
  ///
  /// This is especially useful to recognize frame pointers and the fact
  /// that epilogues can restore stack pointers from frame pointer values.
  /// This is only tracked in Basic Blocks that are known to be reachable
  /// from an entry block. For blocks not (yet) known to be reachable from
  /// an entry block, the optional does not contain a value.
  std::optional<SmallDenseMap<MCPhysReg, int64_t, 2>> Reg2MaxOffset;
  // FIXME: It seems that conceptually it does not make sense to
  // track wheterh the SP value is currently at a fixed offset from
  // the value it was at function entry.
  /// SPFixedOffsetFromOrig indicates whether the current SP value is
  /// a constant fixed offset from the SP value at the function start.
  std::optional<int64_t> SPFixedOffsetFromOrig;
  // LastStackGrowingInsts keep track of the set of most recent stack growing
  // instructions on all possible paths. This is used to improve diagnostic
  // messages.
  SmallSet<MCInstReference, 1> LastStackGrowingInsts;
  State() : MaxOffsetSinceLastProbe(0), SPFixedOffsetFromOrig(0) {}

  State &operator&=(const State &StateIn) {
    MaxOffsetSinceLastProbe &= StateIn.MaxOffsetSinceLastProbe;

    SmallVector<MCPhysReg, 1> RegConstValuesToRemove;
    for (auto Reg2ConstValue : RegConstValues) {
      const MCPhysReg R(Reg2ConstValue.first);
      const uint64_t ConstValue(Reg2ConstValue.second);
      auto SInReg2ConstValue = StateIn.RegConstValues.find(R);
      if (SInReg2ConstValue == StateIn.RegConstValues.end())
        RegConstValuesToRemove.push_back(R);
      else if (Reg2ConstValue.second != SInReg2ConstValue->second) {
        RegConstValuesToRemove.push_back(R);
        addToMaxMap(RegMaxValues, R, ConstValue);
      }
    }
    for (MCPhysReg R : RegConstValuesToRemove)
      RegConstValues.erase(R);

    SmallVector<MCPhysReg, 1> RegMaxValuesToRemove;
    for (auto Reg2MaxValue : RegMaxValues) {
      const MCPhysReg R(Reg2MaxValue.first);
      auto SInReg2MaxValue = StateIn.RegMaxValues.find(R);
      if (SInReg2MaxValue == StateIn.RegMaxValues.end())
        RegMaxValuesToRemove.push_back(R);
      else
        Reg2MaxValue.second =
            std::max(Reg2MaxValue.second, SInReg2MaxValue->second);
    }
    for (MCPhysReg R : RegMaxValuesToRemove)
      RegMaxValues.erase(R);

    if (!SPFixedOffsetFromOrig || !StateIn.SPFixedOffsetFromOrig)
      SPFixedOffsetFromOrig.reset();
    else if (*SPFixedOffsetFromOrig != *StateIn.SPFixedOffsetFromOrig)
      SPFixedOffsetFromOrig.reset();

    if (StateIn.Reg2MaxOffset && Reg2MaxOffset) {
      SmallDenseMap<MCPhysReg, int64_t, 2> MergedMap;
      for (auto R2MaxOff : *Reg2MaxOffset) {
        const MCPhysReg R = R2MaxOff.first;
        if (auto SIn_R2MaxOff = StateIn.Reg2MaxOffset->find(R);
            SIn_R2MaxOff != StateIn.Reg2MaxOffset->end())
          MergedMap[R] = std::max(R2MaxOff.second, SIn_R2MaxOff->second);
      }
      Reg2MaxOffset = MergedMap;
    } else if (StateIn.Reg2MaxOffset && !Reg2MaxOffset) {
      Reg2MaxOffset = StateIn.Reg2MaxOffset;
    }

    for (auto I : StateIn.LastStackGrowingInsts)
      LastStackGrowingInsts.insert(I);
    return *this;
  }
  bool operator==(const State &RHS) const {
    return MaxOffsetSinceLastProbe == RHS.MaxOffsetSinceLastProbe &&
           RegConstValues == RHS.RegConstValues &&
           RegMaxValues == RHS.RegMaxValues &&
           SPFixedOffsetFromOrig == RHS.SPFixedOffsetFromOrig &&
           Reg2MaxOffset == RHS.Reg2MaxOffset;
  }
  bool operator!=(const State &RHS) const { return !((*this) == RHS); }
};

void print_reg(raw_ostream &OS, MCPhysReg Reg, const BinaryContext *BC) {
  if (!BC)
    OS << "R" << Reg;
  else {
    RegStatePrinter RegStatePrinter(*BC);
    BitVector BV(BC->MRI->getNumRegs(), false);
    BV.set(Reg);
    RegStatePrinter.print(OS, BV);
  }
}

template <class T, unsigned N>
void PrintRegMap(raw_ostream &OS, const SmallDenseMap<MCPhysReg, T, N> &M,
                 const BinaryContext *BC = nullptr) {
  for (auto Reg2Value : M) {
    print_reg(OS, Reg2Value.first, BC);
    OS << ":" << Reg2Value.second << ",";
  }
}

raw_ostream &print_state(raw_ostream &OS, const State &S,
                         const BinaryContext *BC = nullptr) {
  OS << "stackclash-state<MaxOff(";
  if (!S.MaxOffsetSinceLastProbe)
    OS << "nonConst";
  else
    OS << *(S.MaxOffsetSinceLastProbe);
  OS << "), RegConstValues(";
  PrintRegMap(OS, S.RegConstValues, BC);
  OS << "), RegMaxValues(";
  PrintRegMap(OS, S.RegMaxValues, BC);
  OS << "),";
  OS << "SPFixedOffsetFromOrig:" << S.SPFixedOffsetFromOrig << ",";
  OS << "Reg2MaxOffset:";
  if (S.Reg2MaxOffset) {
    OS << "(";
    PrintRegMap(OS, *S.Reg2MaxOffset, BC);
    OS << ")";
  } else
    OS << "None";
  OS << ",";
  OS << "LastStackGrowingInsts(" << S.LastStackGrowingInsts.size() << ")>";
  return OS;
}

raw_ostream &operator<<(raw_ostream &OS, const State &S) {
  return print_state(OS, S);
}

} // namespace

class StackClashStatePrinter {
  const BinaryContext &BC;

public:
  void print(raw_ostream &OS, const State &S) const { print_state(OS, S, &BC); }
  explicit StackClashStatePrinter(const BinaryContext &BC) : BC(BC) {}
};

class StackClashDFAnalysis
    : public DataflowAnalysis<StackClashDFAnalysis, State, false /*Forward*/,
                              StackClashStatePrinter> {
  using Parent = DataflowAnalysis<StackClashDFAnalysis, State, false,
                                  StackClashStatePrinter>;
  friend Parent;

public:
  StackClashDFAnalysis(BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocId)
      : Parent(BF, AllocId), NumRegs(BF.getBinaryContext().MRI->getNumRegs()),
        BF(BF) {}
  virtual ~StackClashDFAnalysis() {}

  void run() { Parent::run(); }

protected:
  const uint16_t NumRegs;
  BinaryFunction &BF;

  void preflight() {}

  State getStartingStateAtBB(const BinaryBasicBlock &BB) {
    State Next;
    if (BB.isEntryPoint())
      Next.Reg2MaxOffset = SmallDenseMap<MCPhysReg, int64_t, 2>();
    return Next;
  }

  State getStartingStateAtPoint(const MCInst &Point) { return State(); }

  void doConfluence(State &StateOut, const State &StateIn) {
    StackClashStatePrinter P(BC);
    LLVM_DEBUG({
      dbgs() << " StackClashDFAnalysis::Confluence(\n";
      dbgs() << "   State 1: ";
      P.print(dbgs(), StateOut);
      dbgs() << "\n";
      dbgs() << "   State 2: ";
      P.print(dbgs(), StateIn);
      dbgs() << ")\n";
    });
    StateOut &= StateIn;
    LLVM_DEBUG({
      dbgs() << "   merged state: ";
      P.print(dbgs(), StateOut);
      dbgs() << "\n";
    });
  }

  State computeNext(const MCInst &Point, const State &Cur) {
    State Next = Cur;
    if (BC.MIB->isCFI(Point))
      return Next;

    StackClashStatePrinter P(BC);
    LLVM_DEBUG({
      dbgs() << " StackClashDFAnalysis::Compute(";
      BC.InstPrinter->printInst(&const_cast<MCInst &>(Point), 0, "", *BC.STI,
                                dbgs());
      dbgs() << ", ";
      P.print(dbgs(), Cur);
      dbgs() << ")\n";
    });

    MCPhysReg ConstValueReg = BC.MIB->getNoRegister();
    int64_t ConstValue;
    if (BC.MIB->isMovConstToReg(Point, ConstValueReg, ConstValue)) {
      LLVM_DEBUG({
        dbgs() << "  Found inst setting Reg to constant value " << ConstValue
               << ":";
        BC.printInstruction(dbgs(), Point);
        dbgs() << "\n";
      });
      Next.RegConstValues[ConstValueReg] = ConstValue;
    }

    MCPhysReg MaxValueReg = BC.MIB->getNoRegister();
    uint64_t MaxValueMask;
    if (BC.MIB->isRetainOnlyLowerBitsInReg(Point, MaxValueReg, MaxValueMask)) {
      LLVM_DEBUG({
        dbgs() << "  Found inst setting upper bound on value in Reg: ";
        BC.printInstruction(dbgs(), Point);
        dbgs() << "    MaxValueReg: " << MaxValueReg
               << "; MaxValueMask: " << MaxValueMask << "\n";
      });
      const uint64_t MaxValueInReg = MaxValueMask;
      auto MaxValueForRegI = Next.RegMaxValues.find(MaxValueReg);
      if (MaxValueForRegI == Next.RegMaxValues.end())
        Next.RegMaxValues[MaxValueReg] = MaxValueInReg;
      else {
        MaxValueForRegI->second =
            std::min(MaxValueForRegI->second, MaxValueInReg);
      }
    }
    // FIXME properly handle register aliases below. E.g. a call
    // should reset call-clobbered registers?
#if 0
    const MCInstrDesc &InstInfo = BC.MIB->Info->get(Point.getOpcode());
    for (MCPhysReg ImplicitDef : InstInfo.implicit_defs())
      if (ImplicitDef != MaxValueReg)
        Next.RegMaxValues.erase(ImplicitDef);
#endif
    for (const MCOperand &Operand : BC.MIB->defOperands(Point)) {
      assert(Operand.isReg());
      if (Operand.getReg() != MaxValueReg)
        Next.RegMaxValues.erase(Operand.getReg());
      if (Operand.getReg() != ConstValueReg)
        Next.RegConstValues.erase(Operand.getReg());
    }

    if (!Next.MaxOffsetSinceLastProbe)
      return Next;

    const MCPhysReg SP = BC.MIB->getStackPointer();
    int64_t StackAccessOffset;
    bool IsStackAccess;

    if ((IsStackAccess = BC.MIB->isStackAccess(Point, StackAccessOffset))) {
      Next.MaxOffsetSinceLastProbe =
          std::min(*Next.MaxOffsetSinceLastProbe, StackAccessOffset);
      LLVM_DEBUG({
        dbgs() << "  Found Stack Access inst: ";
        BC.printInstruction(dbgs(), Point);
        dbgs() << "    Offset: " << StackAccessOffset
               << "; new MaxOffsetSinceLastProbe: "
               << *Next.MaxOffsetSinceLastProbe << "\n";
      });
    }

    MCPhysReg FixedOffsetRegJustSet = BC.MIB->getNoRegister();
    if (auto OC = BC.MIB->getOffsetChange(Point, Cur.RegConstValues,
                                          Cur.RegMaxValues))
      if (Next.Reg2MaxOffset) {
        if (OC.FromReg == SP) {
          (*Next.Reg2MaxOffset)[OC.ToReg] = *Cur.MaxOffsetSinceLastProbe;
          FixedOffsetRegJustSet = OC.ToReg;
        } else if (auto I = Cur.Reg2MaxOffset->find(OC.FromReg);
                   I != Cur.Reg2MaxOffset->end()) {
          (*Next.Reg2MaxOffset)[OC.ToReg] = (*I).second;
          FixedOffsetRegJustSet = OC.ToReg;
        }
      }
    if (Next.Reg2MaxOffset)
      for (const MCOperand &Operand : BC.MIB->defOperands(Point)) {
        if (Operand.getReg() != FixedOffsetRegJustSet) {
          Next.Reg2MaxOffset->erase(Operand.getReg());
          LLVM_DEBUG({
            dbgs() << "   - Removed Reg " << Operand.getReg()
                   << " from Next.Reg2MaxOffset"
                   << ". On instruction:";
            BC.printInstruction(dbgs(), Point);
            dbgs() << "\n";
          });
        }
      }

    if (BC.MIB->hasDefOfPhysReg(Point, SP)) {
      // Next, validate that  we can track by how much the SP
      // value changes. This should be a constant amount.
      // Else, if we cannot determine the fixed offset, mark this location as
      // needing a report that this potentially changes the SP value by a
      // non-constant amount, and hence violates stack-clash properties.
      Next.LastStackGrowingInsts.insert(MCInstInBBReference::get(&Point, BF));
      if (auto OC = BC.MIB->getOffsetChange(Point, Cur.RegConstValues,
                                            Cur.RegMaxValues);
          OC && OC.ToReg == SP) {
        if (OC.FromReg == SP) {
          assert(OC.MaxOffsetChange);
          if (*OC.MaxOffsetChange < 0)
            Next.MaxOffsetSinceLastProbe =
                *Next.MaxOffsetSinceLastProbe - *OC.MaxOffsetChange;
          if (OC.OffsetChange && Next.SPFixedOffsetFromOrig)
            Next.SPFixedOffsetFromOrig =
                *Next.SPFixedOffsetFromOrig + *OC.OffsetChange;
            // FIXME: add test case for this if test.
#if 0
        if (IsPreIndexOffsetChange)
          Next.MaxOffsetSinceLastProbe =
              *Next.MaxOffsetSinceLastProbe - StackAccessOffset;
#endif
          LLVM_DEBUG({
            dbgs() << "  Found SP Offset change: ";
            BC.printInstruction(dbgs(), Point);
            dbgs() << "    OffsetChange: " << OC.OffsetChange
                   << "; MaxOffsetChange: " << OC.MaxOffsetChange
                   << "; new MaxOffsetSinceLastProbe: "
                   << Next.MaxOffsetSinceLastProbe
                   << "; new SPFixedOffsetFromOrig: "
                   << Next.SPFixedOffsetFromOrig
                   << "; IsStackAccess:" << IsStackAccess
                   << "; StackAccessOffset: " << StackAccessOffset << "\n";
          });
          assert(!OC.IsPreIndexOffsetChange || IsStackAccess);
          assert(*Next.MaxOffsetSinceLastProbe >= 0);
        } else if (
            Cur.Reg2MaxOffset && Cur.Reg2MaxOffset->contains(OC.FromReg) &&
            OC.OffsetChange ==
                0 /* FIXME: also handle other offset changes if needed. */) {
          const int64_t MaxOffset = Cur.Reg2MaxOffset->find(OC.FromReg)->second;
          Next.MaxOffsetSinceLastProbe = MaxOffset;
        }
      } else {
        Next.MaxOffsetSinceLastProbe.reset();
        Next.SPFixedOffsetFromOrig
            .reset(); // FIXME - should I make this the empty set?
        LLVM_DEBUG({
          dbgs() << "  Found non-const SP Offset change: ";
          BC.printInstruction(dbgs(), Point);
        });
      }
    }

    return Next;
  }

  StringRef getAnnotationName() const {
    return StringRef("StackClashDFAnalysis");
  }

public:
};

// Assume 4K pages (for now). FIXME: make this configurable.
const int PAGESIZE = 64 * 1024;

void StackClashAnalysis::runOnFunction(
    BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocatorId) {
  LLVM_DEBUG({
    dbgs() << "Analyzing in function " << BF.getPrintName() << ", AllocatorId "
           << AllocatorId << "\n";
  });
  LLVM_DEBUG({ BF.dump(); });

  if (BF.hasCFG()) {
    StackClashDFAnalysis SCDFA(BF, AllocatorId);
    SCDFA.run();
    BinaryContext &BC = BF.getBinaryContext();
    const MCPhysReg SP = BC.MIB->getStackPointer();

    // Now iterate over the basic blocks to indicate where something needs
    // to be reported.
    for (BinaryBasicBlock &BB : BF) {
      bool TooLargeOffsetAlreadyReported = false;
      for (size_t I = 0; I < BB.size(); ++I) {
        MCInst &Inst = BB.getInstructionAtIndex(I);
        SmallVector<StackClashIssue, 2> SCIAnnotations;

        // Check if MaxOffsetSinceLastProbe grows larger than a page; report
        // only once per basic block.
        State S = *SCDFA.getStateBefore(Inst);
        // FIXME: think long and hard about the justification to allow
        // the latest stack probe to (temporarily) at most be 2 page sizes
        // worth from the top of stack. At the moment, I think this is
        // necessary, as right after the stack grows by a new page, the
        // last probe is necessarily at least 1 page removed from the current
        // new top-of-stack.
        if (!TooLargeOffsetAlreadyReported && S.MaxOffsetSinceLastProbe &&
            *S.MaxOffsetSinceLastProbe >= 2 * PAGESIZE) {
          TooLargeOffsetAlreadyReported = true;
          LLVM_DEBUG({
            dbgs() << "  Found SP Offset change with not all pages accessed: ";
            BC.printInstruction(dbgs(), Inst);
            dbgs() << "    State: " << S << "\n";
          });
          // Add an annotation to report
          SCIAnnotations.push_back(StackClashIssue::createNotAllPagesWritten(
              *S.MaxOffsetSinceLastProbe, S.LastStackGrowingInsts));
        }

        // Next, validate that we can track by how much the SP
        // value changes. This should be a constant amount.
        // Else, if we cannot determine the fixed offset, mark this location
        // as needing a report that this potentially changes the SP value by a
        // non-constant amount, and hence violates stack-clash properties.
        if (auto OC =
                BC.MIB->getOffsetChange(Inst, S.RegConstValues, S.RegMaxValues);
            BC.MIB->hasDefOfPhysReg(Inst, SP) &&
            !(OC && OC.ToReg == SP && OC.FromReg == SP)) {
          // If this is a register move from a register that we know contains
          // a value that is a fixed offset from the SP at the start of the
          // function into the SP, then we know this is probably fine.
          // Typical case is moving the frame pointer to the stack pointer
          // in the function epilogue.
          bool IsFixedRegToSPMove = OC && OC.ToReg == SP && S.Reg2MaxOffset &&
                                    S.Reg2MaxOffset->contains(OC.FromReg);
          if (IsFixedRegToSPMove) {
            S.MaxOffsetSinceLastProbe =
                S.Reg2MaxOffset->find(OC.FromReg)->second;
          } else {
            // mark to report that this may be an SP change that is not a
            // constant amount.
            LLVM_DEBUG({
              dbgs() << "  Found SP Offset change that may not be a constant "
                        "amount: ";
              BC.printInstruction(dbgs(), Inst);
            });
            SCIAnnotations.push_back(
                StackClashIssue::createNonConstantSPChangeData());
          }
        }
        // merge and add annotations
        if (SCIAnnotations.size() == 0)
          continue;
        StackClashIssue MergedSCI = StackClashIssue::createEmpty();
        for (StackClashIssue &SCI : SCIAnnotations)
          MergedSCI |= SCI;
        BC.MIB->addAnnotation(Inst, gadgetAnnotationIndex, MergedSCI);
      }
    }
  }
}

namespace {

void reportFoundGadget(const BinaryContext &BC, const BinaryBasicBlock &BB,
                       const MCInst &Inst, unsigned int gadgetAnnotationIndex) {
  StackClashIssue SCI =
      BC.MIB->getAnnotationAs<StackClashIssue>(Inst, gadgetAnnotationIndex);
  BinaryFunction *BF = BB.getParent();
  auto BFName = BF->getPrintName();
  if (SCI.NotAllPagesWritten) {
    outs() << "\nGS-STACKCLASH: large SP increase without necessary accesses "
              "found in function "
           << BFName;
    // outs() << ", at address " << llvm::format("%x", Inst.getAddress()) <<
    // "\n";
    outs() << "\n";
    outs() << "  The following instruction(s) increase the stack:\n";
    for (auto MCInstRef : SCI.LastStackGrowingInsts) {
      outs() << "  * ";
      BC.printInstruction(outs(), MCInstRef, MCInstRef.getAddress());
    }
    outs() << "  This instruction changes the SP next, making the "
              "closest-to-top-of-stack "
              "access happen at an offset of "
           << *SCI.MaxOffsetSinceLastProbe
           << ", which is larger than the assumed page size (" << PAGESIZE
           << "):\n  * ";
    MCInstInBBReference NextSPInst = MCInstInBBReference::get(&Inst, *BF);
    BC.printInstruction(outs(), NextSPInst, NextSPInst.getAddress());
  }
  if (SCI.NonConstantSPChange) {
    outs() << "\nGS-STACKCLASH: non-constant SP change found in function "
           << BFName;
    outs() << "\n";
    outs() << "  instruction ";
    BC.printInstruction(outs(), Inst,
                        MCInstInBBReference::get(&Inst, *BF).getAddress());
  }
}

} // namespace

void StackClashAnalysis::runOnFunctions(BinaryContext &BC) {
  gadgetAnnotationIndex =
      BC.MIB->getOrCreateAnnotationIndex("stackclash-gadget");

  ParallelUtilities::WorkFuncWithAllocTy WorkFun =
      [&](BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocatorId) {
        runOnFunction(BF, AllocatorId);
      };

  ParallelUtilities::PredicateTy SkipFunc = [&](const BinaryFunction &BF) {
    return false; // BF.shouldPreserveNops();
  };

  ParallelUtilities::runOnEachFunctionWithUniqueAllocId(
      BC, ParallelUtilities::SchedulingPolicy::SP_INST_LINEAR, WorkFun,
      SkipFunc, "StackClashAnalysis");

  for (BinaryFunction *BF : BC.getAllBinaryFunctions())
    if (BF->hasCFG()) {
      for (BinaryBasicBlock &BB : *BF) {
        for (size_t I = 0; I < BB.size(); ++I) {
          MCInst &Inst = BB.getInstructionAtIndex(I);
          if (BC.MIB->hasAnnotation(Inst, gadgetAnnotationIndex)) {
            reportFoundGadget(BC, BB, Inst, gadgetAnnotationIndex);
          }
        }
      }
    }
}

} // namespace bolt
} // namespace llvm
