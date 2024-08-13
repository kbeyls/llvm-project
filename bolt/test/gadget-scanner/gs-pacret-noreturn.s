// Check that there are no false positives related to no-return functions.

// RUN: %clang %cflags -march=armv8.3-a -mbranch-protection=pac-ret %s %p/../Inputs/asm_main.c -o %t.exe
// RUN: llvm-bolt-gadget-scanner --scanners=pacret %t.exe --noreturnfuncs="doesnotreturn1/1" 2>&1 | FileCheck -check-prefix=CHECK --allow-empty %s


// Verify that we can also detect gadgets across basic blocks

        .globl f_call_returning
        .type   f_call_returning,@function
f_call_returning:
        bl      call_returning
        ret
        .size f_call_returning, .-f_call_returning
// CHECK-LABEL:     GS-PACRET: non-protected ret found in function f_call_returning, basic block .L{{[^,]+}}, at address
// CHECK-NEXT:  The return instruction is     {{[0-9a-f]+}}:       ret
// CHECK-NEXT:  The 1 instructions that write to the return register after any authentication are:
// CHECK-NEXT:  1.     {{[0-9a-f]+}}:      bl call_returning

        .type doesnotreturn1,@function
doesnotreturn1:
        stp     x29, x30, [sp, #-16]!
        ldp     x29, x30, [sp], #16
        brk 1
        ret
        .size doesnotreturn1, .-doesnotreturn1
// CHECK-NOT: function doesnotreturn1

        .type doesnotreturn2,@function
doesnotreturn2:
        cmp x0, x1
        bgt .L1
        bl memcpy@PLT
.L1:
        brk 1
        // BOLT used to insert an artificial ret here. This test case checks that no longer happens.
        ret
        .size doesnotreturn2, .-doesnotreturn2
// CHECK-NOT: function doesnotreturn2

        .type gadget_entirely_in_dead_code,@function
gadget_entirely_in_dead_code:
        stp     x29, x30, [sp, #-16]!
        brk 1
        ldp     x29, x30, [sp], #16
        ret
        .size gadget_entirely_in_dead_code, .-gadget_entirely_in_dead_code
// CHECK-LABEL:     GS-PACRET: non-protected ret found in function gadget_entirely_in_dead_code{{(/[0-9])?}}, basic block .L{{[^,]+}}, at address
// CHECK-NEXT:  The return instruction is     {{[0-9a-f]+}}:       ret
// CHECK-NEXT:  The 1 instructions that write to the return register after any authentication are:
// CHECK-NEXT:  1.     {{[0-9a-f]+}}:      ldp     x29, x30, [sp], #0x10


        .globl f_call_noreturn
        .type   f_call_noreturn,@function
f_call_noreturn:
        bl      doesnotreturn1
        ret
        .size f_call_noreturn, .-f_call_noreturn
// CHECK-NOT: function f_call_noreturn
