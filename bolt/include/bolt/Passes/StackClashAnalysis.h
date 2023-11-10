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
#include <algorithm>
#include <optional>
#include <queue>

namespace llvm {
namespace bolt {

typedef std::optional<int64_t> MaxOffsetSinceLastProbeT;

inline
MaxOffsetSinceLastProbeT &operator&=(MaxOffsetSinceLastProbeT &LHS,
                                     const MaxOffsetSinceLastProbeT &RHS) {
  if (LHS && RHS)
    LHS = std::max(*LHS, *RHS);
  else
    LHS.reset();
  return LHS;
}

struct StackClashIssue {
  bool NotAllPagesWritten;
  bool NonConstantSPChange;
  // The following fields are only used in case NotAllPagesWritten is true.
  MaxOffsetSinceLastProbeT
      MaxOffsetSinceLastProbe; //  AccessedPagesT AccessedPages;
  SmallSet<MCInstReference, 1> LastStackGrowingInsts;

protected:
  StackClashIssue() {}

public:
  static StackClashIssue createEmpty() {
    StackClashIssue SCI;
    SCI.NotAllPagesWritten = false;
    SCI.NonConstantSPChange = false;
    SCI.MaxOffsetSinceLastProbe = 0;
    return SCI;
  }
  static StackClashIssue createNotAllPagesWritten(
      const MaxOffsetSinceLastProbeT MaxOffsetSinceLastProbe,
      const SmallSet<MCInstReference, 1> &LastStackGrowingInsts) {
    StackClashIssue SCI;
    SCI.NotAllPagesWritten = true;
    SCI.NonConstantSPChange = false;
    SCI.MaxOffsetSinceLastProbe = MaxOffsetSinceLastProbe;
    SCI.LastStackGrowingInsts = LastStackGrowingInsts;
    return SCI;
  }
  static StackClashIssue createNonConstantSPChangeData() {
    StackClashIssue SCI;
    SCI.NotAllPagesWritten = false;
    SCI.NonConstantSPChange = true;
    return SCI;
  }
  bool operator==(const StackClashIssue &RHS) const {
    return NotAllPagesWritten == RHS.NotAllPagesWritten &&
           NonConstantSPChange == RHS.NonConstantSPChange &&
           MaxOffsetSinceLastProbe == RHS.MaxOffsetSinceLastProbe;
  }
  StackClashIssue &operator|=(const StackClashIssue &RHS) {
    NonConstantSPChange |= RHS.NonConstantSPChange;
    if (RHS.NotAllPagesWritten) {
      NotAllPagesWritten = true;
      MaxOffsetSinceLastProbe &= RHS.MaxOffsetSinceLastProbe;
      for (MCInstReference R : RHS.LastStackGrowingInsts)
        LastStackGrowingInsts.insert(R);
    }
    return *this;
  }
};

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
