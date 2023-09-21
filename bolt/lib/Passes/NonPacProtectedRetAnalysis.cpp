//===- bolt/Passes/NonPacProtectedRetAnalysis.cpp -------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements a pass that looks for any AArch64 return instructions
// that may not be protected by PAuth authentication instructions when needed.
//
// When needed = the register used to return (almost always X30), is potentially
// written to between the AUThentication instruction and the RETurn instruction.
// As all (at least compiler-generated) pac-ret code generation will generate
// the AUT and the RET in a single basic block, we only look for patterns within
// a basic block. At worst, we will get false positives due to this, not false
// negatives.
//
//===----------------------------------------------------------------------===//

#include "bolt/Passes/NonPacProtectedRetAnalysis.h"
#include "bolt/Core/ParallelUtilities.h"
#include "bolt/Passes/DataflowAnalysis.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/MC/MCInst.h"
#include "llvm/Support/Format.h"

#define DEBUG_TYPE "bolt-nonpacprotectedret"

namespace llvm {
namespace bolt {

raw_ostream &operator<<(raw_ostream &OS, const MCInstInBBReference &Ref) {
  OS << "MCInstBBRef<";
  if (Ref.BB == nullptr)
    OS << "BB:(null)";
  else
    OS << "BB:" << Ref.BB->getName() << ":" << Ref.BBIndex;
  OS << ">";
  return OS;
}

raw_ostream &operator<<(raw_ostream &OS, const MCInstInBFReference &Ref) {
  OS << "MCInstBFRef<";
  if (Ref.BF == nullptr)
    OS << "BF:(null)";
  else
    OS << "BF:" << Ref.BF->getPrintName() << ":" << Ref.getOffset();
  OS << ">";
  return OS;
}

raw_ostream &operator<<(raw_ostream &OS, const MCInstReference &Ref) {
  switch (Ref.CurrentLocation) {
  case MCInstReference::_BinaryBasicBlock:
    OS << Ref.u.BBRef;
    return OS;
  case MCInstReference::_BinaryFunction:
    OS << Ref.u.BFRef;
    return OS;
  }
  llvm_unreachable("");
}

raw_ostream &operator<<(raw_ostream &OS,
                        const NonPacProtectedRetGadget &NPPRG) {
  OS << "pac-ret-gadget<";
  OS << "Ret:" << NPPRG.RetInst << ", ";
  OS << "Overwriting:" << NPPRG.OverwritingRetRegInst << ">";
  return OS;
}

#if 0
struct State {
  unsigned RetReg; // if different from NoRegister, this is the register used by
                   // the next return instruction.
                   // TODO: what to do when there are multiple such registers?
                   // This should be a SmallSet/SmallVector?
};
#endif

// We assume that there will be very few gadgets, or alternatively, the
// far majority of code will have the required security properties.
// Therefore, we assume that the most efficient method to find those
// gadgets is to first scan in each function if there is a violation of
// the security property at all. If there is, we can do a second scan
// which tracks a lot more detail, so that we can produce good
// diagnostic messages.

// As state, store for each register if at this program point:
// (a) it is used next by a RETurn instruction, to determine the address to
// "return" to.
// (b) the register is in an "unauthenticated" state, i.e. written
// to by an operation that isn't an authentication instruction.
// TODO:
// union of LiveRetRegs: simply the union.
// union of UnauthenticatedRegs: simply the union.
// but for reporting, we also need to keep track of which MCInst made the
// LiveRetReg dirty...

// Let's try an alternative way:
// We should report any time when:
// A register is "Ret-live", (or for PAuthABI, any time a pointer is used that
// should be signed before storing to memory, i.e. at least all code pointers),
// if it is: (a) Used by such an instruction, without being overwritten in
// between. Therefore, in the analysis, we need to track which registers (and
// for reporting purposes, leading up to which ret instructions) are live. Then,
// with a simple scan we can check each instruction if they do write to any such
// "Ret-live", or "RawCodePointerLive" registers.

// Yet another way: let's track the registers that have been written (def-ed),
// since last authenticated. Those are exactly the registers containing values
// that should not be trusted (as they could have changed since the last time
// they were authenticated). For pac-ret, any return using such a register is
// a gadget to be reported. For PAuthABI, any indirect control flow using such
// a register should be reported?
struct State {
  // FIXME: for tracking PAuthABI, probably the SmallSet needs to be made bigger
  // (5 or 10?)
  // SmallSet<llvm::MCPhysReg, 1> LiveRawPointerRegs;
  BitVector NonAutClobRegs;
  // SmallSet<const MCInst *, 1> ClobberingInsts;

  State() {}
  State(uint16_t NumRegs)
      : NonAutClobRegs(NumRegs, false) //, UnauthenticatedRegs(NumRegs),
                         // ClobberingInsts()
  {}
  State &operator|=(const State &StateIn) {
    NonAutClobRegs |= StateIn.NonAutClobRegs;
    // for (auto Reg : StateIn.LiveRawPointerRegs)
    //   LiveRawPointerRegs.insert(Reg);
    //  for (auto c : StateIn.ClobberingInsts)
    //    ClobberingInsts.insert(c);
    return *this;
  }
  bool operator==(const State &RHS) const {
    return NonAutClobRegs == RHS.NonAutClobRegs;
    //    &&UnauthenticatedRegs == RHS.UnauthenticatedRegs &&ClobberingInsts ==
    //        RHS.ClobberingInsts;
  }
  bool operator!=(const State &RHS) const { return !((*this) == RHS); }
};

// StateWithInsts represents the same as State, but additionally tracks which
// the set of last instructions is that set each clobbered register.
struct StateWithInsts : public State {
  std::vector<SmallPtrSet<const MCInst *, 4>> LastInstWritingReg;
  StateWithInsts() : State() {}
  StateWithInsts(uint16_t NumRegs, uint16_t NumRegsToTrack)
      : State(NumRegs), LastInstWritingReg(NumRegsToTrack/*, SmallPtrSet<const MCInst*,4>()*/) {}
  StateWithInsts &operator|=(const StateWithInsts &StateIn) {
    State::operator|=(StateIn);
    for (unsigned I = 0; I < LastInstWritingReg.size(); ++I)
      for (auto J : StateIn.LastInstWritingReg[I])
        LastInstWritingReg[I].insert(J);
    return *this;
  }
  bool operator==(const StateWithInsts &RHS) const {
    if (State::operator!=(RHS))
      return false;
    return LastInstWritingReg == RHS.LastInstWritingReg;
  }
  bool operator!=(const StateWithInsts &RHS) const { return !((*this) == RHS); }
};

raw_ostream &operator<<(raw_ostream &OS, const State &S) {
  OS << "pacret-state<";
  OS << "NonAutClobRegs: " << S.NonAutClobRegs;
  OS << ">";
  return OS;
}

raw_ostream &operator<<(raw_ostream &OS, const StateWithInsts &S) {
  OS << "pacret-stateWI<";
  OS << "NonAutClobRegs: " << S.NonAutClobRegs;
  OS << "Insts: ";
  for (auto Set : S.LastInstWritingReg) {
    OS << "(";
    for (auto MCInstP : Set)
      OS << MCInstP << " ";
    OS << ")";
  }
  OS << ">";
  return OS;
}

class PacStatePrinter {
public:
  void print(raw_ostream &OS, const State &State) const;
  explicit PacStatePrinter(const BinaryContext &BC) : BC(BC) {}

private:
  const BinaryContext &BC;
};

void PacStatePrinter::print(raw_ostream &OS, const State &S) const {
  RegStatePrinter RegStatePrinter(BC);
  OS << "pacret-state<";
  OS << "NonAutClobRegs: ";
  RegStatePrinter.print(OS, S.NonAutClobRegs);
  OS << ">";
}

class PacStateWIPrinter {
public:
  void print(raw_ostream &OS, const StateWithInsts &State) const;
  explicit PacStateWIPrinter(const BinaryContext &BC) : BC(BC) {}

private:
  const BinaryContext &BC;
};

void PacStateWIPrinter::print(raw_ostream &OS, const StateWithInsts &S) const {
  RegStatePrinter RegStatePrinter(BC);
  OS << "pacret-state<";
  OS << "NonAutClobRegs: ";
  RegStatePrinter.print(OS, S.NonAutClobRegs);
  OS << "Insts: ";
  for (auto Set : S.LastInstWritingReg) {
    OS << "(";
    for (auto MCInstP : Set)
      OS << MCInstP << " ";
    OS << ")";
  }
  OS << ">";
}

class PacRetAnalysis
    : public DataflowAnalysis<PacRetAnalysis, State, false /*Backward*/,
                              PacStatePrinter> {
  using Parent =
      DataflowAnalysis<PacRetAnalysis, State, false, PacStatePrinter>;
  friend Parent;

public:
  PacRetAnalysis(BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocId)
      : Parent(BF, AllocId), NumRegs(BF.getBinaryContext().MRI->getNumRegs()) {}
  virtual ~PacRetAnalysis() {}

  void run() { Parent::run(); }

protected:
  const uint16_t NumRegs;

  void preflight() {}

  State getStartingStateAtBB(const BinaryBasicBlock &BB) {
    return State(NumRegs);
  }

  State getStartingStateAtPoint(const MCInst &Point) { return State(NumRegs); }

  void doConfluence(State &StateOut, const State &StateIn) {
    PacStatePrinter P(BC);
    LLVM_DEBUG({
      dbgs() << " PacRetAnalysis::Confluence(\n";
      dbgs() << "   State 1: ";
      P.print(dbgs(), StateOut);
      dbgs() << "\n";
      dbgs() << "   State 2: ";
      P.print(dbgs(), StateIn);
      dbgs() << ")\n";
    });
    StateOut |= StateIn;
    LLVM_DEBUG({
      dbgs() << "   merged state: ";
      P.print(dbgs(), StateOut);
      dbgs() << "\n";
    });
  }

  State computeNext(const MCInst &Point, const State &Cur) {
    PacStatePrinter P(BC);
    LLVM_DEBUG({
      dbgs() << " PacRetAnalysis::Compute(";
      BC.InstPrinter->printInst(&const_cast<MCInst &>(Point), 0, "", *BC.STI,
                                dbgs());
      dbgs() << ", ";
      P.print(dbgs(), Cur);
      dbgs() << ")\n";
    });

    State Next = Cur;
    BitVector Written = BitVector(NumRegs, false);
    BC.MIB->getWrittenRegs(Point, Written);
    Next.NonAutClobRegs |= Written;
    MCPhysReg AutReg = BC.MIB->getAuthenticatedReg(Point);
    if (AutReg != BC.MIB->getNoRegister()) {
      Next.NonAutClobRegs.reset(
          BC.MIB->getAliases(AutReg, /*OnlySmaller=*/true));
    }
    return Next;
  }

  StringRef getAnnotationName() const { return StringRef("PacRetAnalysis"); }
};

class PacRetWIAnalysis
    : public DataflowAnalysis<PacRetWIAnalysis, StateWithInsts,
                              false /*Backward*/, PacStateWIPrinter> {
  using Parent = DataflowAnalysis<PacRetWIAnalysis, StateWithInsts, false,
                                  PacStateWIPrinter>;
  friend Parent;

public:
  PacRetWIAnalysis(BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocId,
                   const std::vector<MCPhysReg> &_RegsToTrackInstsFor)
      : Parent(BF, AllocId), NumRegs(BF.getBinaryContext().MRI->getNumRegs()),
        RegsToTrackInstsFor(_RegsToTrackInstsFor),
        _Reg2StateIdx(*std::max_element(RegsToTrackInstsFor.begin(),
                                        RegsToTrackInstsFor.end()) +
                          1,
                      -1) {
    for (unsigned I = 0; I < RegsToTrackInstsFor.size(); ++I)
      _Reg2StateIdx[RegsToTrackInstsFor[I]] = I;
  }
  virtual ~PacRetWIAnalysis() {}

  void run() { Parent::run(); }

protected:
  const uint16_t NumRegs;
  const std::vector<MCPhysReg> RegsToTrackInstsFor;
  std::vector<uint16_t> _Reg2StateIdx;

  bool TrackReg(MCPhysReg Reg) {
    for (auto R : RegsToTrackInstsFor)
      if (R == Reg)
        return true;
    return false;
  }
  uint16_t Reg2StateIdx(MCPhysReg Reg) {
    assert(Reg < _Reg2StateIdx.size());
    return _Reg2StateIdx[Reg];
  }

  void preflight() {}

  StateWithInsts getStartingStateAtBB(const BinaryBasicBlock &BB) {
    return StateWithInsts(NumRegs, RegsToTrackInstsFor.size());
  }

  StateWithInsts getStartingStateAtPoint(const MCInst &Point) {
    return StateWithInsts(NumRegs, RegsToTrackInstsFor.size());
  }

  void doConfluence(StateWithInsts &StateOut, const StateWithInsts &StateIn) {
    PacStateWIPrinter P(BC);
    LLVM_DEBUG({
      dbgs() << " PacRetWIAnalysis::Confluence(\n";
      dbgs() << "   State 1: ";
      P.print(dbgs(), StateOut);
      dbgs() << "\n";
      dbgs() << "   State 2: ";
      P.print(dbgs(), StateIn);
      dbgs() << ")\n";
    });
    StateOut |= StateIn;
    LLVM_DEBUG({
      dbgs() << "   merged state: ";
      P.print(dbgs(), StateOut);
      dbgs() << "\n";
    });
  }

  StateWithInsts computeNext(const MCInst &Point, const StateWithInsts &Cur) {
    PacStateWIPrinter P(BC);
    LLVM_DEBUG({
      dbgs() << " PacRetWIAnalysis::Compute(";
      BC.InstPrinter->printInst(&const_cast<MCInst &>(Point), 0, "", *BC.STI,
                                dbgs());
      dbgs() << ", ";
      P.print(dbgs(), Cur);
      dbgs() << ")\n";
    });

    StateWithInsts Next = Cur;
    BitVector Written = BitVector(NumRegs, false);
    BC.MIB->getWrittenRegs(Point, Written);
    Next.NonAutClobRegs |= Written;
    for (auto WrittenReg : Written.set_bits()) {
      if (TrackReg(WrittenReg)) {
        Next.LastInstWritingReg[Reg2StateIdx(WrittenReg)] = {};
        Next.LastInstWritingReg[Reg2StateIdx(WrittenReg)].insert(&Point);
      }
    }
    MCPhysReg AutReg = BC.MIB->getAuthenticatedReg(Point);
    if (AutReg != BC.MIB->getNoRegister()) {
      Next.NonAutClobRegs.reset(
          BC.MIB->getAliases(AutReg, /*OnlySmaller=*/true));
      if (TrackReg(AutReg))
        Next.LastInstWritingReg[Reg2StateIdx(AutReg)] = {};
    }
    LLVM_DEBUG({
      dbgs() << "  .. result: (";
      P.print(dbgs(), Next);
      dbgs() << ")\n";
    });
    return Next;
  }

  StringRef getAnnotationName() const { return StringRef("PacRetWIAnalysis"); }
};

void reset_track_state(const BinaryContext &BC, unsigned &RetReg,
                       std::optional<MCInstReference> &RetInst) {
  RetInst = {};
  RetReg = BC.MIB->getNoRegister();
}

// Returns true if a non-protected return was found that should be
// reported.
void processOneInst(const MCInstReference Inst, const BinaryContext &BC,
                    unsigned &RetReg, std::optional<MCInstReference> &RetInst,
                    const unsigned gadgetAnnotationIndex) {
  if (BC.MIB->isReturn(Inst)) {
    RetInst = Inst;
    // RetInstOffset = I;
    //  Returns should always be the last instruction in the basic block
    //  assert(NrInstrScanned == 0);
    RetReg = BC.MIB->getRegUsedAsRetDest(Inst);
    LLVM_DEBUG({
      dbgs() << ".. return instruction found using register ";
      BC.InstPrinter->printRegName(dbgs(), MCRegister(RetReg));
      dbgs() << "\n";
    });
  }
  if (!RetInst)
    return; // false; // skip to following instruction. continue;
  if (BC.MIB->hasDefOfPhysReg(Inst, RetReg) &&
      !BC.MIB->isAuthenticationOfReg(Inst, RetReg)) {
    // We did see a RET, we did not see an AUT yet, and now we're seeing
    // a write to RetReg. In other words, register RetReg gets modified
    // between the last AUT and the RET: it means this RET is not
    // pac-ret-protected.
    LLVM_DEBUG({
      dbgs() << ".. instruction found that writes register ";
      BC.InstPrinter->printRegName(dbgs(), MCRegister(RetReg));
      dbgs() << " : ";
      BC.InstPrinter->printInst(&(MCInst &)Inst, 0, "", *BC.STI, dbgs());
      dbgs() << "\n ";
    });
    {
      LLVM_DEBUG({
        dbgs() << ".. Therefore, the return instruction is not pac-ret "
                  "protected.\n";
      });
      // Non-protected ret found
      assert(RetInst.has_value());
      BC.MIB->addAnnotation(*RetInst, gadgetAnnotationIndex,
                            NonPacProtectedRetGadget(*RetInst, Inst));
    }
    reset_track_state(BC, RetReg, RetInst);
    return;
  }

  // Gadget scanning state needs to be reset when encountering an
  // authentication instruction or an unconditional branch.
  if (BC.MIB->isAuthenticationOfReg(Inst, RetReg) ||
      BC.MIB->isUnconditionalBranch(Inst)) {
    LLVM_DEBUG({
      dbgs() << ".. auth instruction found using register ";
      BC.InstPrinter->printRegName(dbgs(), MCRegister(RetReg));
      dbgs() << " : ";
      BC.InstPrinter->printInst(&(MCInst &)Inst, 0, "", *BC.STI, dbgs());
      dbgs() << "\n ";
    });
    reset_track_state(BC, RetReg, RetInst);
    return;
  }
  return;
}

template <class PRAnalysis>
SmallSet<MCPhysReg, 1> NonPacProtectedRetAnalysis::ComputeDFState(
    PRAnalysis &PRA, BinaryFunction &BF,
    MCPlusBuilder::AllocatorIdTy AllocatorId) {
  PRA.run();
  LLVM_DEBUG({
    dbgs() << " After PacRetAnalysis:\n";
    BF.dump();
  });
  // Now scan the CFG for instructions that overwrite any of the live
  // LiveRawPointerRegs. If it's not an authentication instruction,
  // that violates the security property.
  SmallSet<MCPhysReg, 1> RetRegsWithGadgets;
  BinaryContext &BC = BF.getBinaryContext();
  for (BinaryBasicBlock &BB : BF) {
    for (int64_t I = BB.size() - 1; I >= 0; --I) {
      MCInst &Inst = BB.getInstructionAtIndex(I);
      if (BC.MIB->isReturn(Inst)) {
        MCPhysReg RetReg = BC.MIB->getRegUsedAsRetDest(Inst);
        LLVM_DEBUG({
          dbgs() << "  Found RET inst: ";
          BC.printInstruction(dbgs(), Inst);
          dbgs() << "    RetReg: " << BC.MRI->getName(RetReg)
                 << "; authenticatesReg: "
                 << BC.MIB->isAuthenticationOfReg(Inst, RetReg) << "\n";
        });
        if (BC.MIB->isAuthenticationOfReg(Inst, RetReg))
          break;
        BitVector DirtyRawRegs = PRA.getStateAt(Inst)->NonAutClobRegs;
        LLVM_DEBUG({
          dbgs() << "  DirtyRawRegs at Ret: ";
          RegStatePrinter RSP(BC);
          RSP.print(dbgs(), DirtyRawRegs);
          dbgs() << "\n";
        });
        DirtyRawRegs &= BC.MIB->getAliases(RetReg, /*OnlySmaller=*/true);
        LLVM_DEBUG({
          dbgs() << "  Intersection with RetReg: ";
          RegStatePrinter RSP(BC);
          RSP.print(dbgs(), DirtyRawRegs);
          dbgs() << "\n";
        });
        if (DirtyRawRegs.any()) {
          // This return instruction needs to be reported
          // First remove the annotation that the first, fast run of
          // the dataflow analysis may have added.
          if (BC.MIB->hasAnnotation(Inst, gadgetAnnotationIndex))
            BC.MIB->removeAnnotation(Inst, gadgetAnnotationIndex);
          BC.MIB->addAnnotation(Inst, gadgetAnnotationIndex,
                                NonPacProtectedRetGadget(
                                    MCInstInBBReference(&BB, I), {} /*, Inst*/),
                                AllocatorId);
#if 0
          LLVM_DEBUG({
            dbgs() << "Added gadget info annotation: ";
#if 1
            BC.InstPrinter->printInst(&const_cast<MCInst &>(Inst), 0, "",
                                      *BC.STI, dbgs());
#endif
            dbgs() << "\n";
          });
#endif
          for (MCPhysReg RetRegWithGadget : DirtyRawRegs.set_bits())
            RetRegsWithGadgets.insert(RetRegWithGadget);
        }
      }
    }
  }
  return RetRegsWithGadgets;
}

void NonPacProtectedRetAnalysis::runOnFunction(
    BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocatorId) {
  LLVM_DEBUG({
    dbgs() << "Analyzing in function " << BF.getPrintName() << ", AllocatorId "
           << AllocatorId << "\n";
  });
  LLVM_DEBUG({ BF.dump(); });

  const BinaryContext &BC = BF.getBinaryContext();
  unsigned RetReg;
  std::optional<MCInstReference> RetInst;
  // unsigned NrInstrScanned = 0;

  if (BF.hasCFG()) {
    PacRetAnalysis PRA(BF, AllocatorId);
    SmallSet<MCPhysReg, 1> RetRegsWithGadgets = ComputeDFState(PRA, BF, AllocatorId);
    if (!RetRegsWithGadgets.empty()) {
      // Redo the analysis, but now also track which instructions last wrote
      // to any of the registers in RetRegsWithGadgets, so that better
      // diagnostics can be produced.
      std::vector<MCPhysReg> RegsToTrack;
      for (MCPhysReg R : RetRegsWithGadgets)
        RegsToTrack.push_back(R);
      PacRetWIAnalysis PRWIA(BF, AllocatorId, RegsToTrack);
      SmallSet<MCPhysReg, 1> RetRegsWithGadgets =
          ComputeDFState(PRWIA, BF, AllocatorId);
    }
  }
  // If for any reason, no CFG could be constructed, there obviously will
  // not be any basic blocks. When there are basic blocks, one needs to
  // iterate over the basic blocks; and then over the instructions in the
  // basic blocks, as the function will no longer have a direct reference to
  // the instructions. In case there are no BBs (no CFG), the instructions
  // are still attached to the BinaryFunction and need to be iterated there.
  //
  if (!BF.hasInstructions()) {
    // FIXME: emit warning.
    return;
  }
  // We scan the whole function sequentially, as that's what an attacker is
  // looking for. By not scanning across control flow, that means we might
  // miss gadgets that are split over non-contiguous basic blocks. FIXME:
  // should this be implemented?
  // If the function does not have a CFG (e.g. is not Simple),
  // still try to scan the instructions ignoring BB boundaries?
  reset_track_state(BC, RetReg, RetInst);
  for (auto I = BF.inst_rbegin(), E = BF.inst_rend(); I != E; ++I) {
    // MCInst &Inst = (*I).second;
    uint32_t Offset = (*I).first;
    processOneInst(MCInstReference(&BF, Offset), BC, RetReg, RetInst,
                   gadgetAnnotationIndex);
  }
}

void reportFoundGadget(const BinaryContext &BC, const MCInst &Inst,
                       unsigned int gadgetAnnotationIndex) {
  auto NPPRG = BC.MIB->getAnnotationAs<NonPacProtectedRetGadget>(
      Inst, gadgetAnnotationIndex);
  MCInstReference RetInst = NPPRG.RetInst;
  BinaryFunction *BF = RetInst.getFunction();
  BinaryBasicBlock *BB = RetInst.getBasicBlock();

  outs() << "GS-PACRET: "
         << "non-protected ret found in function " << BF->getPrintName();
  if (BB)
    outs() << ", basic block " << BB->getName();
  outs() << ", at address " << llvm::format("%x", RetInst.getAddress()) << "\n";
  if (BB)
    BB->dump();
  else if (NPPRG.OverwritingRetRegInst) {
    assert(NPPRG.OverwritingRetRegInst->CurrentLocation ==
           MCInstReference::_BinaryFunction);
    assert(RetInst.CurrentLocation == MCInstReference::_BinaryFunction);
    MCInstInBFReference InstRef = NPPRG.OverwritingRetRegInst->u.BFRef;
    bool printInst = false;
    for (auto I = BF->inst_begin(), E = BF->inst_end(); I != E; ++I) {
      if ((*I).first == InstRef.getOffset())
        printInst = true;
      if (printInst)
        BC.printInstruction(outs(), (*I).second, (*I).first, BF);
      if ((*I).first == RetInst.u.BFRef.getOffset())
        break;
    }
  }
}

void NonPacProtectedRetAnalysis::runOnFunctions(BinaryContext &BC) {
  gadgetAnnotationIndex = BC.MIB->getOrCreateAnnotationIndex("pacret-gadget");

  ParallelUtilities::WorkFuncWithAllocTy WorkFun =
      [&](BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocatorId) {
        runOnFunction(BF, AllocatorId);
      };

  ParallelUtilities::PredicateTy SkipFunc = [&](const BinaryFunction &BF) {
    return false; // BF.shouldPreserveNops();
  };

  ParallelUtilities::runOnEachFunctionWithUniqueAllocId(
      BC, ParallelUtilities::SchedulingPolicy::SP_INST_LINEAR, WorkFun,
      SkipFunc, "NonPacProtectedRetAnalysis");

  for (BinaryFunction *BF : BC.getAllBinaryFunctions())
    if (BF->hasCFG()) {
#if 0
      for (BinaryBasicBlock &BB : *BF) {
        LLVM_DEBUG({
          dbgs() << " After PacRetAnalysis:\n";
          BB.dump();
        });
#else
      for (BinaryBasicBlock &BB : *BF) {
        for (int64_t I = BB.size() - 1; I >= 0; --I) {
          MCInst &Inst = BB.getInstructionAtIndex(I);
          if (BC.MIB->hasAnnotation(Inst, gadgetAnnotationIndex)) {
            reportFoundGadget(BC, Inst, gadgetAnnotationIndex);
          }
        }
#endif
      }
    } else {
      for (auto I = BF->inst_begin(), E = BF->inst_end(); I != E; ++I) {
        const MCInst &Inst = (*I).second;
        if (BC.MIB->hasAnnotation(Inst, gadgetAnnotationIndex)) {
          reportFoundGadget(BC, Inst, gadgetAnnotationIndex);
        }
      }
    }
}

} // namespace bolt
} // namespace llvm