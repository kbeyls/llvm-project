// RUN: %clang %cflags %s %p/../Inputs/asm_main.c -o %t.exe
// RUN: llvm-bolt-gadget-scanner --scanners=stack-clash %t.exe 2>&1 | FileCheck -check-prefix=CHECK --allow-empty %s

        .text

        .global f_fixed_large_stack
        .type   f_fixed_large_stack , %function
f_fixed_large_stack :
        sub     sp, sp, #32768
        ldr     x0, [sp, 32704]
        add     sp, sp, 32768
        ret
        .size   f_fixed_large_stack , .-f_fixed_large_stack
// CHECK-LABEL: GS-STACKCLASH: large SP increase without necessary accesses found in function f_fixed_large_stack
// CHECK-NEXT:    The following instruction(s) increase the stack:
// CHECK-NEXT:    * {{[0-9a-f]+}}:      sub     sp, sp, #0x8, lsl #12
// CHECK-NEXT:    This instruction changes the SP next, while not all pages allocated by the previous instructions have been accessed since:
// CHECK-NEXT:    * {{[0-9a-f]+}}:      add     sp, sp, #0x8, lsl #12
// CHECK-NEXT:    Pages seen as accessed in between the SP changes: 9:10000000

// verify that no other issues are reported:
// CHECK-NOT: GS-STACKCLASH:


// TODO: mov     x12, 32000
// CHEck stack adjustment by register with contant: sub     sp, sp, x12

// TODO: check access with constant:
//        add     x0, sp, 16384
//        ldr     w0, [x0, 15608]

