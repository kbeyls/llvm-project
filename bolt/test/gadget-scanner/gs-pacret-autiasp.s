// RUN: %clang %cflags -mbranch-protection=pac-ret %s %p/../Inputs/asm_main.c -o %t.exe
// RUN: llvm-bolt-gadget-scanner %t.exe 2>&1 | FileCheck -check-prefix=CHECK --allow-empty %s

        .text
        .globl  f
        .type   f,@function
f:
// %bb.0:
        hint    #25
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp
        bl      g
        add     x0, x0, #3
        ldp     x29, x30, [sp], #16             // 16-byte Folded Reload
        // hint    #29
// CHECK: GS-PACRET: non-protected ret found in function f, basic block .LBB00
        ret
.Lfunc_end0:
        .size   f, .Lfunc_end0-f
