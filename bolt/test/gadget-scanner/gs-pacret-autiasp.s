// RUN: %clang %cflags -mbranch-protection=pac-ret %s %p/../Inputs/asm_main.c -o %t.exe
// RUN: llvm-bolt-gadget-scanner %t.exe 2>&1 | FileCheck -check-prefix=CHECK --allow-empty %s

        .text
        .globl  f1
        .type   f1,@function
f1:
        hint    #25
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp
        bl      g
        add     x0, x0, #3
        ldp     x29, x30, [sp], #16             // 16-byte Folded Reload
        // paciasp
// CHECK: GS-PACRET: non-protected ret found in function f1, basic block .LBB00
        ret
        .size f1, .-f1

        .globl  f_paciasp
        .type   f_paciasp,@function
f_paciasp:
        hint    #25
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp
        bl      g
        add     x0, x0, #3
        ldp     x29, x30, [sp], #16             // 16-byte Folded Reload
        autiasp
// CHECK-NOT: function f_paciasp
        ret
        .size f_paciasp, .-f_paciasp
