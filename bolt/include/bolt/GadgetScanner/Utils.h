//===- bolt/Passes/StackClashAnalysis.h -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef BOLT_GADGETSCANNER_UTILS_H
#define BOLT_GADGETSCANNER_UTILS_H

#include "bolt/Core/BinaryBasicBlock.h"
#include "bolt/Core/BinaryFunction.h"

namespace llvm {
namespace bolt {

/// @brief  MCInstReference represents a reference to an MCInst as stored either
/// in a BinaryFunction (i.e. before a CFG is created), or in a BinaryBasicBlock
/// (after a CFG is created). It aims to store the necessary information to be
/// able to find the specific MCInst in either the BinaryFunction or
/// BinaryBasicBlock data structures later, so that e.g. the InputAddress of
/// the corresponding instruction can be computed.

struct MCInstInBBReference {
  BinaryBasicBlock *BB;
  int64_t BBIndex;
  MCInstInBBReference(BinaryBasicBlock *_BB, int64_t _BBIndex)
      : BB(_BB), BBIndex(_BBIndex) {}
  MCInstInBBReference() : BB(nullptr), BBIndex(0) {}
  static MCInstInBBReference get(const MCInst *Inst, BinaryFunction &BF) {
    for (BinaryBasicBlock& BB : BF)
      for (size_t I = 0; I < BB.size(); ++I)
        if (Inst == &(BB.getInstructionAtIndex(I)))
          return MCInstInBBReference(&BB, I);
    return {};
  }
  bool operator==(const MCInstInBBReference &RHS) const {
    return BB == RHS.BB && BBIndex == RHS.BBIndex;
  }
  bool operator<(const MCInstInBBReference &RHS) const {
    if (BB != RHS.BB)
      return BB < RHS.BB;
    return BBIndex < RHS.BBIndex;
  }
  operator MCInst &() const {
    assert(BB != nullptr);
    return BB->getInstructionAtIndex(BBIndex);
  }
  uint64_t getAddress() const {
    // 4 bytes per instruction on AArch64;
    return BB->getFunction()->getAddress() + BB->getOffset() + BBIndex * 4;
  }
};

raw_ostream &operator<<(raw_ostream &OS, const MCInstInBBReference &);

struct MCInstInBFReference {
  BinaryFunction *BF;
  uint32_t Offset;
  MCInstInBFReference(BinaryFunction *_BF, uint32_t _Offset)
      : BF(_BF), Offset(_Offset) {}
  MCInstInBFReference() : BF(nullptr) {}
  bool operator==(const MCInstInBFReference &RHS) const {
    return BF == RHS.BF && Offset == RHS.Offset;
  }
  bool operator<(const MCInstInBFReference &RHS) const {
    if (BF != RHS.BF)
      return BF < RHS.BF;
    return Offset < RHS.Offset;
  }
  operator MCInst &() const {
    assert(BF != nullptr);
    return *(BF->getInstructionAtOffset(Offset));
  }

  uint64_t getOffset() const { return Offset; }

  uint64_t getAddress() const {
    // 4 bytes per instruction on AArch64;
    return BF->getAddress() + getOffset();
  }
};

raw_ostream &operator<<(raw_ostream &OS, const MCInstInBFReference &);

struct MCInstReference {
  enum StoredIn { _BinaryFunction, _BinaryBasicBlock };
  StoredIn CurrentLocation;
  union U {
    MCInstInBBReference BBRef;
    MCInstInBFReference BFRef;
    U(MCInstInBBReference _BBRef) : BBRef(_BBRef) {}
    U(MCInstInBFReference _BFRef) : BFRef(_BFRef) {}
  } u;
  MCInstReference(MCInstInBBReference _BBRef)
      : CurrentLocation(_BinaryBasicBlock), u(_BBRef) {}
  MCInstReference(MCInstInBFReference _BFRef)
      : CurrentLocation(_BinaryFunction), u(_BFRef) {}
  MCInstReference(BinaryBasicBlock *BB, int64_t BBIndex)
      : MCInstReference(MCInstInBBReference(BB, BBIndex)) {}
  MCInstReference(BinaryFunction *BF, uint32_t Offset)
      : MCInstReference(MCInstInBFReference(BF, Offset)) {}

  bool operator<(const MCInstReference &RHS) const {
    if (CurrentLocation != RHS.CurrentLocation)
      return CurrentLocation < RHS.CurrentLocation;
    switch (CurrentLocation) {
    case _BinaryBasicBlock:
      return u.BBRef < RHS.u.BBRef;
    case _BinaryFunction:
      return u.BFRef < RHS.u.BFRef;
    }
    llvm_unreachable("");
  }

  bool operator==(const MCInstReference &RHS) const {
    if (CurrentLocation != RHS.CurrentLocation)
      return false;
    switch (CurrentLocation) {
    case _BinaryBasicBlock:
      return u.BBRef == RHS.u.BBRef;
    case _BinaryFunction:
      return u.BFRef == RHS.u.BFRef;
    }
    llvm_unreachable("");
  }

  operator MCInst &() const {
    switch (CurrentLocation) {
    case _BinaryBasicBlock:
      return u.BBRef;
    case _BinaryFunction:
      return u.BFRef;
    }
    llvm_unreachable("");
  }

  uint64_t getAddress() const {
    switch (CurrentLocation) {
    case _BinaryBasicBlock:
      return u.BBRef.getAddress();
    case _BinaryFunction:
      return u.BFRef.getAddress();
    }
    llvm_unreachable("");
  }

  BinaryFunction *getFunction() const {
    switch (CurrentLocation) {
    case _BinaryFunction:
      return u.BFRef.BF;
    case _BinaryBasicBlock:
      return u.BBRef.BB->getFunction();
    }
    llvm_unreachable("");
  }

  BinaryBasicBlock *getBasicBlock() const {
    switch (CurrentLocation) {
    case _BinaryFunction:
      return nullptr;
    case _BinaryBasicBlock:
      return u.BBRef.BB;
    }
    llvm_unreachable("");
  }
};

raw_ostream &operator<<(raw_ostream &OS, const MCInstReference &);

} // namespace bolt
} // namespace llvm

#endif