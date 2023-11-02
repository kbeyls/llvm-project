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
#include "llvm/MC/MCInst.h"
#include "llvm/Support/Format.h"

#define DEBUG_TYPE "bolt-stackclash"

namespace llvm {
namespace bolt {

raw_ostream &operator<<(raw_ostream &OS, const StackClashIssue &G) {
  OS << "stackclash-gadget<>";
  return OS;
}

namespace {

// To be able to compute whether always an access happens on every stack page
// as the stack grows, at least the following (sub-)analyses are needed:
//
// 1. Track which register contain a constant value (as they often are used
//    to adjust the stack pointer).
// 2. Track where the stack pointer gets adjusted to grow the stack, and if
//    it's with a constant amount.
// 3. When the stack grows, track how many pages worth it grows by, which/how
//    many pages remain without an access to it.
// 4. Track which accesses are the first accesses that access such an as-yet
//    not-yet-accessed page.
// Where exactly should an error be reported on? When is the latest time the
// program should have made an access to every newly "allocated" stack page?
// As a first attempt, we could keep it simple and simply demand that all
// newly allocated pages must have been accessed before either
// (a) a next stack growth or shrink happens, or
// (b) the end of the function (this should never happen - if a function grows
//     the stack, it should also shrink the stack, so case (a) should cover all
//     code?)
//
// Step 1 - let's start by implementing detecting an issue on a bare minimal
// example. Therefore, implement (2), (3), (4) and (a).

struct State {
  // The different states to track are:
  // State 1: everything fine: all newly allocated stack pages have been
  // accessed. State 2: there are newly allocated stack pages, not yet accessed.
  // Indicate which
  //          newly allocated pages have and which ones have not been accessed.
  // Attempt 1 to store this state: "simply" efficiently record which pages
  // (described in terms of the current SP value) have not been accessed yet.
  AccessedPagesT AccessedPages;
  SmallSet<MCInstReference, 1> LastStackGrowingInsts;
  // bool FlaggedForReporting = false;
  State() {}
#if 0
  void copyWithoutReportingInfo(const State &S) {
    AccessedPages = S.AccessedPages;
  }
#endif
  // void flagNotAllPagesWritten(const BitVector &AccessedPages) {}

  State &operator&=(const State &StateIn) {
    // We can only be sure if a page is accessed, if it's accessed on both
    // paths reaching here.
    if (StateIn.AccessedPages.size() > AccessedPages.size())
      AccessedPages.resize(StateIn.AccessedPages.size());
    AccessedPages &= StateIn.AccessedPages;
    for (auto I : StateIn.LastStackGrowingInsts)
      LastStackGrowingInsts.insert(I);
    return *this;
  }
  bool operator==(const State &RHS) const {
    return AccessedPages == RHS.AccessedPages;
  }
  bool operator!=(const State &RHS) const { return !((*this) == RHS); }
};

raw_ostream &operator<<(raw_ostream &OS, const State &S) {
  OS << "stackclash-state<AP(" << S.AccessedPages << "), LastStackGrowingInsts("
     << S.LastStackGrowingInsts.size() << ")>";
  return OS;
}

} // namespace

class StackClashStatePrinter {
public:
  void print(raw_ostream &OS, const State &S) const;
  explicit StackClashStatePrinter(const BinaryContext &BC) : BC(BC) {}

private:
  const BinaryContext &BC;
};

void StackClashStatePrinter::print(raw_ostream &OS, const State &S) const {
  OS << S;
}

class StackClashDFAnalysis
    : public DataflowAnalysis<StackClashDFAnalysis, State, false /*Forward*/,
                              StackClashStatePrinter> {
  using Parent = DataflowAnalysis<StackClashDFAnalysis, State, false,
                                  StackClashStatePrinter>;
  friend Parent;

public:
  StackClashDFAnalysis(BinaryFunction &BF, MCPlusBuilder::AllocatorIdTy AllocId)
      : Parent(BF, AllocId), NumRegs(BF.getBinaryContext().MRI->getNumRegs()),
        BF(BF) {}
  virtual ~StackClashDFAnalysis() {}

  void run() { Parent::run(); }

protected:
  const uint16_t NumRegs;
  BinaryFunction &BF;

  // Assume 4K pages (for now). FIXME: make this configurable.
  const int PAGESIZE = 4096;

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
    StateOut &= StateIn;
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
    // Next = Cur; //.copyWithoutReportingInfo(Cur);

    const MCPhysReg SP = BC.MIB->getStackPointer();

    if (BC.MIB->hasDefOfPhysReg(Point, SP)) {
#if 0
      // The SP value changes. Therefore, check that all new pages allocated
      // since the previous SP value change have been accessed. If not, mark
      // this location as needing a diagnostic to be reported.
      if (!Cur.AccessedPages.all())
        Next.flagNotAllPagesWritten(Cur.AccessedPages);
#endif

      // Next, validate that validate that we can track by how much the SP
      // value changes. This should be a constant amount.
      // Else, if we cannot determine the fixed offset, mark this location as
      // needing a report that this potentially changes the SP value by a
      // non-constant amount, and hence violates stack-clash properties.
      int64_t OffsetChange;
      if (BC.MIB->getOffsetChange(
              OffsetChange, Point, SP
              /*TODO: something to communicate constant values in register*/)) {
        // Start tracking that we need accesses to the number of new pages on
        // the stack.
        int NrPages = 0;
        // Assume a down-growing stack
        if (OffsetChange < 0)
          // FIXME: verify that rounding down is correct.
          NrPages = (-OffsetChange) / PAGESIZE;
        LLVM_DEBUG({
          dbgs() << "  Found SP Offset change: ";
          BC.printInstruction(dbgs(), Point);
          dbgs() << "    OffsetChange: " << OffsetChange
                 << "; NrPages: " << NrPages << "\n";
        });
        Next.AccessedPages = AccessedPagesT(NrPages, false);
        Next.LastStackGrowingInsts.insert(MCInstInBBReference::get(&Point, BF));
      } else {
#if 0
        // mark to report that this may be an SP change that is not a constant
        // amount.
        Next.flagNonConstantSPChange();
#endif
      }
    }

    int64_t StackOffset;
    if (BC.MIB->isStackAccess(Point, StackOffset)) {
      assert(StackOffset >= 0);
      const int pageNr = StackOffset / PAGESIZE;
      LLVM_DEBUG({
        dbgs() << "  Found Stack Access inst: ";
        BC.printInstruction(dbgs(), Point);
        dbgs() << "    Offset: " << StackOffset << "; pageNr: " << pageNr
               << "\n";
      });
      // FIXME: this shouldn't be an assert - incorrect codegen could trigger
      // this.
      assert((size_t)pageNr < Next.AccessedPages.size());
      Next.AccessedPages.set(pageNr);
    }

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
    SCDFA.run();
    BinaryContext &BC = BF.getBinaryContext();
    const MCPhysReg SP = BC.MIB->getStackPointer();

    // Now iterate over the basic blocks to indicate where something needs
    // to be reported.
    for (BinaryBasicBlock &BB : BF) {
      for (size_t I = 0; I < BB.size(); ++I) {
        MCInst &Inst = BB.getInstructionAtIndex(I);
        if (BC.MIB->hasDefOfPhysReg(Inst, SP)) {
          // The SP value changes. Therefore, check that all new pages allocated
          // since the previous SP value change have been accessed. If not, mark
          // this location as needing a diagnostic to be reported.
          State S = *SCDFA.getStateBefore(Inst);
          if (!S.AccessedPages.all()) {
            LLVM_DEBUG({
              dbgs()
                  << "  Found SP Offset change with not all pages accessed: ";
              BC.printInstruction(dbgs(), Inst);
              dbgs() << "    AccessedPages state: " << S << "\n";
            });
            // Add an annotation to report
            BC.MIB->addAnnotation(
                Inst, gadgetAnnotationIndex,
                StackClashIssue::createNotAllPagesWritten(
                    S.AccessedPages, S.LastStackGrowingInsts));
          }

          // Next, validate that validate that we can track by how much the SP
          // value changes. This should be a constant amount.
          // Else, if we cannot determine the fixed offset, mark this location
          // as needing a report that this potentially changes the SP value by a
          // non-constant amount, and hence violates stack-clash properties.
          int64_t OffsetChange;
          if (!BC.MIB->getOffsetChange(
              OffsetChange, Inst, SP
              /*TODO: something to communicate constant values in register*/)) {
            // mark to report that this may be an SP change that is not a
            // constant amount.
            LLVM_DEBUG({
              dbgs() << "  Found SP Offset change that may not be a constant "
                        "amount: ";
              BC.printInstruction(dbgs(), Inst);
            });
            BC.MIB->addAnnotation(
                Inst, gadgetAnnotationIndex,
                StackClashIssue::createNonConstantSPChangeData());
          }
        }
      }
    }
  }
}

namespace {

void reportFoundGadget(const BinaryContext &BC, const BinaryBasicBlock &BB,
                       const MCInst &Inst, unsigned int gadgetAnnotationIndex) {
  StackClashIssue SCI =
      BC.MIB->getAnnotationAs<StackClashIssue>(Inst, gadgetAnnotationIndex);
  BinaryFunction *BF = BB.getParent();
  auto BFName = BF->getPrintName();
  switch (SCI.kind) {
  case StackClashIssue::NotAllPagesWritten: {
    outs() << "\nGS-STACKCLASH: large SP increase without necessary accesses "
              "found in "
              "function "
           << BFName;
    // outs() << ", at address " << llvm::format("%x", Inst.getAddress()) <<
    // "\n";
    outs() << "\n";
    outs() << "  The following instruction(s) increase the stack:\n";
    for (auto MCInstRef : SCI.LastStackGrowingInsts) {
      outs() << "  * ";
      BC.printInstruction(outs(), MCInstRef, MCInstRef.getAddress());
    }
    outs() << "  This instruction changes the SP next, while not all pages "
              "allocated "
           << "by the previous instructions have been accessed since:\n  * ";
    MCInstInBBReference NextSPInst = MCInstInBBReference::get(&Inst, *BF);
    BC.printInstruction(outs(), NextSPInst, NextSPInst.getAddress());
    int64_t OffsetChange;
    BC.MIB->getOffsetChange(OffsetChange, Inst, BC.MIB->getStackPointer());
    outs() << "  Pages seen as accessed in between the SP changes: "
           << SCI.AccessedPages << "\n";
  } break;
  case StackClashIssue::NonConstantSPChange:
    outs() << "\nGS-STACKCLASH: non-constant SP change found in function "
           << BFName;
    outs() << "\n";
    outs() << "  instruction ";
    BC.printInstruction(outs(), Inst /*, BF->getAddress() + (*I).first, BF*/);
    break;
  }
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
            reportFoundGadget(BC, BB, Inst, gadgetAnnotationIndex);
          }
        }
      }
    }
}

} // namespace bolt
} // namespace llvm
