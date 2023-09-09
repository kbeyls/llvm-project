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

#include <cstdio>

#define DEBUG_TYPE "bolt-nonpacprotectedret"

namespace llvm {
namespace bolt {

void NonPacProtectedRetAnalysis::runOnFunction(BinaryFunction &BF) {
  const BinaryContext &BC = BF.getBinaryContext();
  for (BinaryBasicBlock &BB : BF) {
    bool RetFound = false;
    bool AuthFound = false;
    unsigned RetReg = BC.MIB->getNoRegister();
    LLVM_DEBUG({
      dbgs() << "Analyzeing in function " << BF.getPrintName()
             << ", basic block " << BB.getName() << "\n";
      BB.dump();
    });
    for (int64_t I = BB.size() - 1; I >= 0; --I) {
      MCInst &Inst = BB.getInstructionAtIndex(I);
      if (BC.MIB->isReturn(Inst)) {
        assert(!RetFound);
        RetFound = true;
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
          break;
        }
      }

      // FIXME: also check that there is no other instr in between defining RetReg.
      // Reads of RetReg are presumably fine (but may result in authentication oracles?)

      if (!RetFound)
        continue;

      if (BC.MIB->isAuthenticationOfReg(Inst, RetReg)) {
        AuthFound = true;
      }
    }
    if (RetFound && !AuthFound) {
      // Non-protected ret found
      // FIXME: need to design something so that output gets buffered as this
      // part can be executed in parallel.
      outs() << "GS-PACRET: "
             << "non-protected ret found in function " << BF.getPrintName()
             << ", basic block " << BB.getName()
             << "\n"; // FIXME: add "at address ..."
      BB.dump();
    }
  }
  // TODO: maybe also scan for authentication oracles? i.e. authentications
  // not followed by a memory access using the authenticated register?
  // TODO: maybe also scan for signing oracles?
}

void NonPacProtectedRetAnalysis::runOnFunctions(BinaryContext &BC) {
  ParallelUtilities::WorkFuncTy WorkFun = [&](BinaryFunction &BF) {
    runOnFunction(BF);
  };

  ParallelUtilities::PredicateTy SkipFunc = [&](const BinaryFunction &BF) {
    return false; // BF.shouldPreserveNops();
  };

  ParallelUtilities::runOnEachFunction(
      BC, ParallelUtilities::SchedulingPolicy::SP_INST_LINEAR, WorkFun,
      SkipFunc, "NonPacProtectedRetAnalysis");
}

} // namespace bolt
} // namespace llvm