// RUN: %clang %cflags -march=armv8.3-a -mbranch-protection=pac-ret %s %p/../Inputs/asm_main.c -o %t.exe
// RUN: llvm-bolt-gadget-scanner %t.exe 2>&1 | FileCheck -check-prefix=CHECK --allow-empty %s


/// Verify that we can also detect gadgets in functions for which a CFG is not constructed
        .globl f_nocfg
        .type   f_nocfg,@function
f_nocfg:
        adr     x0, .l1
        br      x0
// CHECK: GS-PACRET: non-protected ret found in function f_nocfg, at address
.l1:
        mov     x30, x22
        ret
        .size f_nocfg, .-f_nocfg

/// Verify multiple RETs in a row do not trigger asserts
        .globl f_mrets
        .type   f_mrets,@function
f_mrets:
        adr     x0, .l2
        br      x0
// CHECK: GS-PACRET: non-protected ret found in function f_mrets, at address
.l2:
        mov     x30, x22
        ret
        ret
        .size f_mrets, .-f_mrets