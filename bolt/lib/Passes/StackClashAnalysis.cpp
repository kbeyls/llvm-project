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

struct State {
  // Store the maximum possible offset to which the stack extends
  // beyond the furthest probe seen.
  MaxOffsetSinceLastProbeT MaxOffsetSinceLastProbe;
  /// RegMaxValues stores registers that we know have a value in the
  /// range [0, MaxValue-1].
  SmallDenseMap<MCPhysReg, uint64_t, 1> RegMaxValues;
  // LastStackGrowingInsts keep track of the set of most recent stack growing
  // instructions on all possible paths. This is used to improve diagnostic
  // messages.
  SmallSet<MCInstReference, 1> LastStackGrowingInsts;
  State() : MaxOffsetSinceLastProbe(0) {}

  State &operator&=(const State &StateIn) {
    MaxOffsetSinceLastProbe &= StateIn.MaxOffsetSinceLastProbe;
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

    for (auto I : StateIn.LastStackGrowingInsts)
      LastStackGrowingInsts.insert(I);
    return *this;
  }
  bool operator==(const State &RHS) const {
    return MaxOffsetSinceLastProbe == RHS.MaxOffsetSinceLastProbe &&
           RegMaxValues == RHS.RegMaxValues;
  }
  bool operator!=(const State &RHS) const { return !((*this) == RHS); }
};

raw_ostream &print_state(raw_ostream &OS, const State &S,
                         const BinaryContext* BC= nullptr) {
  OS << "stackclash-state<MaxOff(";
  if (!S.MaxOffsetSinceLastProbe)
    OS << "nonConst";
  else
    OS << *(S.MaxOffsetSinceLastProbe);
  OS << "), RegMaxValues(";
  for (auto Reg2MaxValue : S.RegMaxValues) {
    if (!BC)
      OS << "R" << Reg2MaxValue.first;
    else {
      RegStatePrinter RegStatePrinter(*BC);
      BitVector BV(BC->MRI->getNumRegs(), false);
      BV.set(Reg2MaxValue.first);
      RegStatePrinter.print(OS, BV);
    }
    OS << ":" << Reg2MaxValue.second << ",";
  }
  OS << "), LastStackGrowingInsts(" << S.LastStackGrowingInsts.size() << ")>";
  return OS;
}

raw_ostream &operator<<(raw_ostream &OS, const State &S) {
  return print_state(OS, S);
}

} // namespace

class StackClashStatePrinter {
  const BinaryContext &BC;

public:
  void print(raw_ostream &OS, const State &S) const {
    print_state(OS, S, &BC);
  }
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

  State getStartingStateAtBB(const BinaryBasicBlock &BB) { return State(); }

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
    }

    if (!Next.MaxOffsetSinceLastProbe)
      return Next;

    const MCPhysReg SP = BC.MIB->getStackPointer();
    bool IsPreIndexOffsetChange = false;
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

    if (BC.MIB->hasDefOfPhysReg(Point, SP)) {
      int64_t OffsetChange;
      // Next, validate that validate that we can track by how much the SP
      // value changes. This should be a constant amount.
      // Else, if we cannot determine the fixed offset, mark this location as
      // needing a report that this potentially changes the SP value by a
      // non-constant amount, and hence violates stack-clash properties.
      Next.LastStackGrowingInsts.insert(MCInstInBBReference::get(&Point, BF));
      if (BC.MIB->getOffsetChange(OffsetChange, Point, SP, Cur.RegMaxValues,
                                  IsPreIndexOffsetChange)) {
        // Start tracking that we need accesses to the number of new pages on
        // the stack.
        if (OffsetChange < 0)
          Next.MaxOffsetSinceLastProbe =
              *Next.MaxOffsetSinceLastProbe - OffsetChange;
          // FIXME: add test case for this if test.
#if 0
        if (IsPreIndexOffsetChange)
          Next.MaxOffsetSinceLastProbe =
              *Next.MaxOffsetSinceLastProbe - StackAccessOffset;
#endif
        LLVM_DEBUG({
          dbgs() << "  Found SP Offset change: ";
          BC.printInstruction(dbgs(), Point);
          dbgs() << "    OffsetChange: " << OffsetChange
                 << "; new MaxOffsetSinceLastProbe: "
                 << *Next.MaxOffsetSinceLastProbe
                 << "; IsStackAccess:" << IsStackAccess
                 << "; StackAccessOffset: " << StackAccessOffset << "\n";
        });
        assert(!IsPreIndexOffsetChange || IsStackAccess);
        assert(*Next.MaxOffsetSinceLastProbe >= 0);
      } else {
        Next.MaxOffsetSinceLastProbe.reset();
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
            *S.MaxOffsetSinceLastProbe >= 2*PAGESIZE) {
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
        int64_t OffsetChange;
        bool tmp;
        if (BC.MIB->hasDefOfPhysReg(Inst, SP) &&
            !BC.MIB->getOffsetChange(OffsetChange, Inst, SP, S.RegMaxValues,
                                     tmp)) {
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
    BC.printInstruction(outs(), Inst /*, BF->getAddress() + (*I).first, BF*/);
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
