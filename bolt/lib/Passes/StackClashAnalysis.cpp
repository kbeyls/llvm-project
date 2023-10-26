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
#include "llvm/ADT/SmallSet.h"
#include "llvm/MC/MCInst.h"
#include "llvm/Support/Format.h"

#define DEBUG_TYPE "bolt-stackclash"

namespace llvm {
namespace bolt {

raw_ostream &operator<<(raw_ostream &OS, const StackClashGadget &G) {
  OS << "stackclash-gadget<>";
  return OS;
}

namespace {

struct State {
  State() {}
  State &operator|=(const State &StateIn) { return *this; }
  bool operator==(const State &RHS) const { return true; }
  bool operator!=(const State &RHS) const { return !((*this) == RHS); }
};

raw_ostream &operator<<(raw_ostream &OS, const State &S) {
  OS << "stackclash-state<";
  OS << ">";
  return OS;
}

} // namespace

class StackClashStatePrinter {
public:
  void print(raw_ostream &OS, const State &State) const;
  explicit StackClashStatePrinter(const BinaryContext &BC) : BC(BC) {}

private:
  const BinaryContext &BC;
};

void StackClashStatePrinter::print(raw_ostream &OS, const State &S) const {
  OS << "stackclash-state<";
  OS << ">";
}

class StackClashDFAnalysis
    : public DataflowAnalysis<StackClashDFAnalysis, State,
                              false /*Backward FIXME: should be forward?*/,
                              StackClashStatePrinter> {
  using Parent = DataflowAnalysis<StackClashDFAnalysis, State, false,
                                  StackClashStatePrinter>;
  friend Parent;

public:
  StackClashDFAnalysis(BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocId)
      : Parent(BF, AllocId), NumRegs(BF.getBinaryContext().MRI->getNumRegs()) {}
  virtual ~StackClashDFAnalysis() {}

  void run() { Parent::run(); }

protected:
  const uint16_t NumRegs;

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
    StateOut |= StateIn;
    LLVM_DEBUG({
      dbgs() << "   merged state: ";
      P.print(dbgs(), StateOut);
      dbgs() << "\n";
    });
  }

  State computeNext(const MCInst &Point, const State &Cur) {
    StackClashStatePrinter P(BC);
    LLVM_DEBUG({
      dbgs() << " StackClashDFAnalysis::Compute(";
      BC.InstPrinter->printInst(&const_cast<MCInst &>(Point), 0, "", *BC.STI,
                                dbgs());
      dbgs() << ", ";
      P.print(dbgs(), Cur);
      dbgs() << ")\n";
    });

    State Next = Cur;
    return Next;
  }

  StringRef getAnnotationName() const {
    return StringRef("StackClashDFAnalysis");
  }

public:
};

void StackClashAnalysis::runOnFunction(
    BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocatorId) {
  LLVM_DEBUG({
    dbgs() << "Analyzing in function " << BF.getPrintName() << ", AllocatorId "
           << AllocatorId << "\n";
  });
  LLVM_DEBUG({ BF.dump(); });

  if (BF.hasCFG()) {
    StackClashDFAnalysis SCDFA(BF, AllocatorId);
  }
}

namespace {

void reportFoundGadget(const BinaryContext &BC, const MCInst &Inst,
                       unsigned int gadgetAnnotationIndex) {
  auto G =
      BC.MIB->getAnnotationAs<StackClashGadget>(Inst, gadgetAnnotationIndex);
#if 0
  BinaryFunction *BF = RetInst.getFunction();
  BinaryBasicBlock *BB = RetInst.getBasicBlock();

  outs() << "\nGS-PACRET: "
         << "non-protected ret found in function " << BF->getPrintName();
  if (BB)
    outs() << ", basic block " << BB->getName();
  outs() << ", at address " << llvm::format("%x", RetInst.getAddress()) << "\n";
#endif
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
        for (int64_t I = BB.size() - 1; I >= 0; --I) {
          MCInst &Inst = BB.getInstructionAtIndex(I);
          if (BC.MIB->hasAnnotation(Inst, gadgetAnnotationIndex)) {
            reportFoundGadget(BC, Inst, gadgetAnnotationIndex);
          }
        }
      }
    }
}

} // namespace bolt
} // namespace llvm