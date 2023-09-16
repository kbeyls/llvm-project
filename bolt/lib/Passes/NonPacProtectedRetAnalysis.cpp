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
    // TODO: reset scanning state
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
    return; // true;
    // break;
  }

  if (BC.MIB->isAuthenticationOfReg(Inst, RetReg)) {
    LLVM_DEBUG({
      dbgs() << ".. auth instruction found using register ";
      BC.InstPrinter->printRegName(dbgs(), MCRegister(RetReg));
      dbgs() << " : ";
      BC.InstPrinter->printInst(&(MCInst &)Inst, 0, "", *BC.STI, dbgs());
      dbgs() << "\n ";
    });
    reset_track_state(BC, RetReg, RetInst);
    return; // false;
    // break;
  }
  return; // false;
}

void NonPacProtectedRetAnalysis::runOnFunction(BinaryFunction &BF) {
  LLVM_DEBUG(
      { dbgs() << "Analyzing in function " << BF.getPrintName() << "\n"; });

  const BinaryContext &BC = BF.getBinaryContext();
  unsigned RetReg;
  std::optional<MCInstReference> RetInst;
  // unsigned NrInstrScanned = 0;

  if (BF.hasCFG()) {
    for (BinaryBasicBlock &BB : BF) {
      reset_track_state(BC, RetReg, RetInst /*, NonPacRetProtected*/);
      LLVM_DEBUG({
        dbgs() << ".. Analyzing basic block " << BB.getName();
        BB.dump();
      });
      for (int64_t I = BB.size() - 1; I >= 0; --I) {
        processOneInst(MCInstReference(&BB, I), BC, RetReg, RetInst,
                       gadgetAnnotationIndex);
      }
    }
    return;
  }
  // If for any reason, no CFG could be constructed, there obviously will not
  // be any basic blocks.
  // When there are basic blocks, one needs to iterate over the basic blocks;
  // and then over the instructions in the basic blocks, as the function will
  // no longer have a direct reference to the instructions.
  // In case there are no BBs (no CFG), the instructions are still attached to
  // the BinaryFunction and need to be iterated there.
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

  ParallelUtilities::WorkFuncTy WorkFun = [&](BinaryFunction &BF) {
    runOnFunction(BF);
  };

  ParallelUtilities::PredicateTy SkipFunc = [&](const BinaryFunction &BF) {
    return false; // BF.shouldPreserveNops();
  };

  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_INST_LINEAR, WorkFun,
      SkipFunc, "NonPacProtectedRetAnalysis");

  for (BinaryFunction *BF : BC.getAllBinaryFunctions())
    if (BF->hasCFG()) {
      for (BinaryBasicBlock &BB : *BF)
        for (int64_t I = BB.size() - 1; I >= 0; --I) {
          MCInst &Inst = BB.getInstructionAtIndex(I);
          if (BC.MIB->hasAnnotation(Inst, gadgetAnnotationIndex)) {
            reportFoundGadget(BC, Inst, gadgetAnnotationIndex);
          }
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