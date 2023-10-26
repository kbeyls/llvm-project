//===- bolt/Passes/StackClashAnalysis.h -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef BOLT_PASSES_STACKCLASHANALYSIS_H
#define BOLT_PASSES_STACKCLASHANALYSIS_H

#include "bolt/Core/BinaryContext.h"
#include "bolt/Core/BinaryFunction.h"
#include "bolt/Passes/BinaryPasses.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/Support/Errc.h"
#include <optional>
#include <queue>

namespace llvm {
namespace bolt {

struct StackClashGadget {
#if 0
// TODO
  MCInstReference RetInst;
  std::vector<MCInstReference> OverwritingRetRegInst;
  /// address of ret instruction? -> not needed.
  /// register of ret instruction?
  bool operator==(const NonPacProtectedRetGadget &RHS) const {
    return RetInst == RHS.RetInst &&
           OverwritingRetRegInst == RHS.OverwritingRetRegInst;
  }
  NonPacProtectedRetGadget(
      MCInstReference _RetInst,
      const std::vector<MCInstReference>& _OverwritingRetRegInst)
      : RetInst(_RetInst), OverwritingRetRegInst(_OverwritingRetRegInst) {}
#endif
};

raw_ostream &operator<<(raw_ostream &OS, const StackClashGadget &G);

class StackClashAnalysis : public BinaryFunctionPass {
  void runOnFunction(BinaryFunction &Function,
                     MCPlusBuilder::AllocatorIdTy AllocatorId);
  template <class PRAnalysis>
  SmallSet<MCPhysReg, 1>
  ComputeDFState(PRAnalysis &PRA, BinaryFunction &BF,
                 MCPlusBuilder::AllocatorIdTy AllocatorId);
  unsigned gadgetAnnotationIndex;

public:
  explicit StackClashAnalysis() : BinaryFunctionPass(false) {}

  const char *getName() const override { return "stack-clash"; }

  /// Pass entry point
  void runOnFunctions(BinaryContext &BC) override;
};

} // namespace bolt
} // namespace llvm

#endif