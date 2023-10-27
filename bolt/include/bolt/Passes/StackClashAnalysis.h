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
#include "bolt/GadgetScanner/Utils.h"
#include "bolt/Passes/BinaryPasses.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/Support/Errc.h"
#include <optional>
#include <queue>

namespace llvm {
namespace bolt {

class AccessedPages : public BitVector {
public:
  AccessedPages() : BitVector() {}
  AccessedPages &operator=(const BitVector &BV) {
    BitVector::operator=(BV);
    return (*this);
  }
  AccessedPages(unsigned size, bool InitVal) : BitVector(size, InitVal) {}
};

inline raw_ostream &operator<<(raw_ostream &OS, const AccessedPages &AP) {
  OS << AP.size() << ":";
  for (unsigned I = 0; I < AP.size(); ++I)
    OS << (AP[I] ? "1" : "0");
  return OS;
}
struct StackClashIssue {
  enum Kind { NotAllPagesWritten, NonConstantSPChange } kind;
  AccessedPages AccessedPages;
  SmallSet<MCInstReference, 1> LastStackGrowingInsts;

protected:
  StackClashIssue() {}

public:
  static StackClashIssue createNotAllPagesWritten(
      const BitVector &AccessedPages,
      const SmallSet<MCInstReference, 1> &LastStackGrowingInsts) {
    StackClashIssue SCI;
    SCI.kind = NotAllPagesWritten;
    SCI.AccessedPages = AccessedPages;
    SCI.LastStackGrowingInsts = LastStackGrowingInsts;
    return SCI;
  }
  static StackClashIssue createNonConstantSPChangeData() {
    StackClashIssue SCI;
    SCI.kind = NonConstantSPChange;
    return SCI;
  }
  bool operator==(const StackClashIssue &RHS) const {
    if (kind != RHS.kind)
      return false;
    switch (kind) {
    case NotAllPagesWritten:
      return AccessedPages == RHS.AccessedPages;
    case NonConstantSPChange:
      return true;
    }
  }
};

#if 0
struct NotAllPagesWritten : public StackClashIssue {
  BitVector AccessedPages;
  NotAllPagesWritten(BitVector AccessedPages) : AccessedPages(AccessedPages) {}
  bool operator==(const NotAllPagesWritten &RHS) const {
    return AccessedPages == RHS.AccessedPages;
  }
};

struct NotConstantSpChange : public StackClashIssue {
  NotConstantSpChange() {}
  bool operator==(const NotConstantSpChange &RHS) const { return true; }
};
#endif

raw_ostream &operator<<(raw_ostream &OS, const StackClashIssue &G);

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