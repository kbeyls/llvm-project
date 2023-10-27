// RUN: %clang %cflags -march=armv8.3-a -mbranch-protection=pac-ret %s %p/../Inputs/asm_main.c -o %t.exe
// RUN: llvm-bolt-gadget-scanner --scanners=pacret %t.exe 2>&1 | FileCheck -check-prefix=CHECK --allow-empty %s


/// Verify that we can also detect gadgets in functions for which a CFG is not constructed
        .globl f_nocfg
        .type   f_nocfg,@function
f_nocfg:
        adr     x0, .l1
        br      x0
// CHECK-LABEL: GS-PACRET: non-protected ret found in function f_nocfg, at address
// CHECK-NEXT:    The return instruction is     {{[0-9a-f]+}}:       ret
// CHECK-NEXT:    The 1 instructions that write to the return register after any authentication are:
// CHECK-NEXT:    1. {{[0-9a-f]+}}: mov x30, x22
// CHECK-NEXT:    This happens in the following single sequence:
// CHECK-NEXT:    {{[0-9a-f]+}}:   br      x0
// CHECK-NEXT:    {{[0-9a-f]+}}:   mov     x30, x22
// CHECK-NEXT:    {{[0-9a-f]+}}:   ret # Offset: 12 # pacret-gadget: pac-ret-gadget<Ret:MCInstBFRef<BF:f_nocfg:12>, Overwriting:[MCInstBFRef<BF:f_nocfg:8> ]>

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
// CHECK-LABEL: GS-PACRET: non-protected ret found in function f_mrets, at address
// CHECK-NEXT:    The return instruction is     {{[0-9a-f]+}}:       ret
// CHECK-NEXT:    The 1 instructions that write to the return register after any authentication are:
// CHECK-NEXT:    1. {{[0-9a-f]+}}: mov x30, x21
// CHECK-NEXT:    This happens in the following single sequence:
// CHECK-NEXT:    {{[0-9a-f]+}}:   br      x0
// CHECK-NEXT:    {{[0-9a-f]+}}:   mov     x30, x21
// CHECK-NEXT:    {{[0-9a-f]+}}:   ret # Offset: 12 # pacret-gadget: pac-ret-gadget<Ret:MCInstBFRef<BF:f_mrets:12>, Overwriting:[MCInstBFRef<BF:f_mrets:8> ]>

.l2:
        mov     x30, x21
        ret
        ret
        .size f_mrets, .-f_mrets

/// Verify that the scanner does not look across unconditional branches, but
/// does look across conditional branches
        .globl f_branches
        .type   f_branches,@function
f_branches:
        adr     x0, 1f
        br      x0
1:
        mov    x30, x0
        b      2f
        ret    x30
// The next CHECK line will verify that there is only one gadget reported on this
// function, and it's not on this instructions.
2:
        mov    x30, x1
        cbz    x0, 3f
        ret    x30
3:
// CHECK-LABEL: GS-PACRET: non-protected ret found in function f_branches, at address
// CHECK-NEXT:    The return instruction is     {{[0-9a-f]+}}:       ret
// CHECK-NEXT:    The 1 instructions that write to the return register after any authentication are:
// CHECK-NEXT:    1. {{[0-9a-f]+}}: mov x30, x1
// CHECK-NEXT:    This happens in the following single sequence:
// CHECK-NEXT:    {{[0-9a-f]+}}:   ret
// CHECK-NEXT:    {{[0-9a-f]+}}:   mov     x30, x1
// CHECK-NEXT:    {{[0-9a-f]+}}:   cbz     x0, .Ltmp4 # Offset: 24
// CHECK-NEXT:    {{[0-9a-f]+}}:   ret # Offset: 28 # pacret-gadget: pac-ret-gadget<Ret:MCInstBFRef<BF:f_branches:28>, Overwriting:[MCInstBFRef<BF:f_branches:20> ]>
// Verify only one gadget is reported on this function:
// CHECK-NOT: GS-PACRET: non-protected ret found in function f_branches
        b      1b
        .size f_branches, .-f_branches
