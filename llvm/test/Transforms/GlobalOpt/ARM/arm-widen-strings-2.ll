; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 5
; RUN: opt < %s -mtriple=arm-none-eabi -passes=globalopt -S | FileCheck %s

@.str = private unnamed_addr constant [62 x i8] c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\00", align 1

define  void @foo()  {
; CHECK-LABEL: define void @foo() local_unnamed_addr {
; CHECK-NEXT:  [[ENTRY:.*:]]
; CHECK-NEXT:    [[SOMETHING:%.*]] = alloca [64 x i8], align 1
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i32(ptr noundef nonnull align 1 dereferenceable(62) [[SOMETHING]], ptr noundef nonnull align 1 dereferenceable(62) @.str, i32 64, i1 false)
; CHECK-NEXT:    [[CALL2:%.*]] = call i32 @bar(ptr nonnull [[SOMETHING]])
; CHECK-NEXT:    ret void
;
entry:
  %something = alloca [62 x i8], align 1
  call void @llvm.memcpy.p0.p0.i32(ptr noundef nonnull align 1 dereferenceable(62) %something, ptr noundef nonnull align 1 dereferenceable(62) @.str, i32 62, i1 false)
  %call2 = call i32 @bar(ptr nonnull %something)
  ret void
}

declare i32 @bar(...)
