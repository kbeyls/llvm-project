//===- bolt/Passes/NonPacProtectedRetAnalysis.h -----------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef BOLT_PASSES_NONPACPROTECTEDRETANALYSIS_H
#define BOLT_PASSES_NONPACPROTECTEDRETANALYSIS_H

#include "bolt/Core/BinaryContext.h"
#include "bolt/Core/BinaryFunction.h"
#include "bolt/Passes/BinaryPasses.h"
#include "llvm/Support/Errc.h"
#include <optional>
#include <queue>

namespace llvm {
namespace bolt {

class NonPacProtectedRetAnalysis : public BinaryFunctionPass {
  void runOnFunction(BinaryFunction &Function);

public:
  explicit NonPacProtectedRetAnalysis()
      : BinaryFunctionPass(false) {}

  const char *getName() const override { return "non-pac-protected-rets"; }

  /// Pass entry point
  void runOnFunctions(BinaryContext &BC) override;
};

} // namespace bolt
} // namespace llvm

#endif