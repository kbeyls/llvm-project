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

void NonPacProtectedRetAnalysis::runOnBB(BinaryFunction &BF,
                                         BinaryBasicBlock &BB) {
  const BinaryContext &BC = BF.getBinaryContext();
  bool RetFound = false;
  bool AuthFound = false;
  unsigned RetReg = BC.MIB->getNoRegister();
  MCInst &RetInst = BB.back();
  int64_t RetInstOffset = -1;
  LLVM_DEBUG({
    dbgs() << "Analyzing in function " << BF.getPrintName() << ", basic block "
           << BB.getName() << "\n";
    BB.dump();
  });
  for (int64_t I = BB.size() - 1; I >= 0; --I) {
    MCInst &Inst = BB.getInstructionAtIndex(I);
    if (BC.MIB->isReturn(Inst)) {
      assert(!RetFound);
      RetFound = true;
      RetInstOffset = I;
      // There should be one register that the return reads, and
      // that's the one being used as the jump target?
      // But what about RETAA etc?
      // FIXME: write test case for RETAA.
      for (unsigned OpIdx = 0, EndIdx = Inst.getNumOperands(); OpIdx < EndIdx;
           ++OpIdx) {
        MCOperand &MO = Inst.getOperand(OpIdx);
        if (!MO.isReg())
          continue;
        RetReg = MO.getReg();
        LLVM_DEBUG({
          dbgs() << ".. return instruction found using register ";
          BC.InstPrinter->printRegName(dbgs(), MCRegister(RetReg));
          dbgs() << " (" << MO << ")\n";
        });
        break;
      }
    }

    if (!RetFound)
      continue;

    if (BC.MIB->isAuthenticationOfReg(Inst, RetReg)) {
      LLVM_DEBUG({
        dbgs() << ".. auth instruction found using register ";
        BC.InstPrinter->printRegName(dbgs(), MCRegister(RetReg));
        dbgs() << " : ";
        BC.InstPrinter->printInst(&Inst, 0, "", *BC.STI, dbgs());
        dbgs() << "\n ";
      });
      AuthFound = true;
      break;
    }

    if (BC.MIB->hasDefOfPhysReg(Inst, RetReg)) {
      break;
    }
  }
  if (RetFound && !AuthFound) {
    // Non-protected ret found
    uint64_t Address =
        BB.getInputAddressRange().first + BF.getAddress() + RetInstOffset * 4;

    BC.MIB->addAnnotation(RetInst, gadgetAnnotationIndex,
                          NonPacProtectedRetGadget(Address));
  }
  // TODO: maybe also scan for authentication oracles? i.e. authentications
  // not followed by a memory access using the authenticated register?
  // TODO: maybe also scan for signing oracles?
}

void NonPacProtectedRetAnalysis::runOnFunction(BinaryFunction &BF) {
  for (BinaryBasicBlock &BB : BF)
    runOnBB(BF, BB);
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

  // FIXME: iterate over all annotations, print out diagnostic which has an
  // annotation. }
  for (BinaryFunction *BF : BC.getAllBinaryFunctions())
    for (BinaryBasicBlock &BB : *BF)
      for (int64_t I = BB.size() - 1; I >= 0; --I) {
        MCInst &Inst = BB.getInstructionAtIndex(I);
        if (BC.MIB->hasAnnotation(Inst, gadgetAnnotationIndex)) {
          outs() << "GS-PACRET: "
                 << "non-protected ret found in function " << BF->getPrintName()
                 << ", basic block " << BB.getName() << ", at address "
                 << llvm::format(
                        "%x", BC.MIB
                                  ->getAnnotationAs<NonPacProtectedRetGadget>(
                                      Inst, gadgetAnnotationIndex)
                                  .Address)
                 << "\n"; // FIXME: add "at address ..."
          BB.dump();
        }
      }
}
} // namespace bolt
} // namespace llvm