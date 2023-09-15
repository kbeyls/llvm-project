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

raw_ostream &operator<<(raw_ostream &OS,
                        const NonPacProtectedRetGadget &NPPRG) {
  OS << "pac-ret-gadget<" << NPPRG.Address << ">";
  return OS;
}

void reset_track_state(const BinaryContext &BC, unsigned &RetReg,
                       MCInst *&RetInst) {
  RetInst = nullptr;
  RetReg = BC.MIB->getNoRegister();
}

// Returns true if a non-protected return was found that should be
// reported.
void processOneInst(MCInst &Inst, const BinaryContext &BC, BinaryFunction &BF,
                    BinaryBasicBlock *BB, unsigned &RetReg, MCInst *&RetInst,
                    const unsigned gadgetAnnotationIndex) {
  if (BC.MIB->isReturn(Inst)) {
    assert(RetInst == nullptr);
    RetInst = &Inst;
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
  if (RetInst == nullptr)
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
      BC.InstPrinter->printInst(&Inst, 0, "", *BC.STI, dbgs());
      dbgs() << "\n ";
    });
    // TODO: reset scanning state
    {
      LLVM_DEBUG({
        dbgs() << ".. Therefore, the return instruction is not pac-ret "
                  "protected.\n";
      });
      // Non-protected ret found
      assert(RetInst != nullptr);
#if 0
      assert(BB != nullptr);

      uint64_t RetAddress =
          BF.getAddress() + BB->getInputAddressRange().second - 4;
#endif
      // FIXME: improve calculation of real RET address.
      BC.MIB->addAnnotation(*RetInst, gadgetAnnotationIndex,
                            NonPacProtectedRetGadget(BF.getAddress()));
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
      BC.InstPrinter->printInst(&Inst, 0, "", *BC.STI, dbgs());
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
  MCInst *RetInst;
  // unsigned NrInstrScanned = 0;

  if (BF.hasCFG()) {
    for (BinaryBasicBlock &BB : BF) {
      reset_track_state(BC, RetReg, RetInst /*, NonPacRetProtected*/);
      LLVM_DEBUG({
        dbgs() << ".. Analyzing basic block " << BB.getName();
        BB.dump();
      });
      for (auto I = BB.rbegin(); I != BB.rend(); I++)
        processOneInst(*I, BC, BF, &BB, RetReg, RetInst, gadgetAnnotationIndex);
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
    MCInst &Inst = (*I).second;
    processOneInst(Inst, BC, BF, nullptr, RetReg, RetInst,
                   gadgetAnnotationIndex);
  }
}

void reportFoundGadget(const BinaryContext &BC,
                       unsigned int gadgetAnnotationIndex, MCInst &Inst,
                       BinaryFunction &BF, BinaryBasicBlock *BB = nullptr) {
  outs() << "GS-PACRET: "
         << "non-protected ret found in function " << BF.getPrintName();
  if (BB != nullptr)
    outs() << ", basic block " << BB->getName();
  outs() << ", at address "
         << llvm::format("%x", BC.MIB
                                   ->getAnnotationAs<NonPacProtectedRetGadget>(
                                       Inst, gadgetAnnotationIndex)
                                   .Address)
         << "\n"; // FIXME: add "at address ..."
                  // BB.dump();
                  // FIXME: print from write inst to ret inst
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
            reportFoundGadget(BC, gadgetAnnotationIndex, Inst, *BF, &BB);
          }
        }
    } else {
      for (auto I = BF->inst_begin(), E = BF->inst_end(); I != E; ++I) {
        MCInst &Inst = (*I).second;
        if (BC.MIB->hasAnnotation(Inst, gadgetAnnotationIndex)) {
          reportFoundGadget(BC, gadgetAnnotationIndex, Inst, *BF);
        }
      }
    }
}

} // namespace bolt
} // namespace llvm