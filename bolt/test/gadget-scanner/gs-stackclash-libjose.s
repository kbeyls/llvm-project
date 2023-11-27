// RUN: %clang %cflags %s %p/../Inputs/asm_main.c -o %t.exe
// RUN: llvm-bolt-gadget-scanner --scanners=stack-clash %t.exe 2>&1 | FileCheck -check-prefix=CHECK --allow-empty %s

        .text
        .global f
        .type   f , %function
f:
   paciasp
   stp     x29, x30, [sp, #-0x60]!
   adrp    x4, #253952
   ldr     x4, [x4, #0xf98]
   mov     x29, sp
   stp     x19, x20, [sp, #0x10]
   mov     x19, x0
   stp     x21, x22, [sp, #0x20]
   stp     x23, x24, [sp, #0x30]
   str     x25, [sp, #0x40]
   sub     sp, sp, #0x10
   ldr     x0, [x4]
   str     x0, [x29, #0x58]
   mov     x0, #0x0
   str     x1, [x19, #0x28]
   str     w2, [x19, #0x30]
   cbz     w2, .Ltmp66

.LFT39:
   mov     x21, x3
   add     x23, x19, #0x28
   mov     w22, #0x1000
   mov     x24, #0x1000
   b       .Ltmp67

.Ltmp70:
   mov     x25, sp
   sub     sp, sp, #0x1, lsl #12
   str     xzr, [sp, #0x400]
   add     x20, sp, #0x10
   str     x20, [x19, #0x40]
   str     w22, [x19, #0x48]
   mov     x0, x23
   mov     w1, #0x0
   blr     x21
   cmn     w0, #0x5
   b.eq    .Ltmp68

.LFT40:
   cmp     w0, #0x1
   b.hi    .Ltmp69

.Ltmp68:
   ldr     x0, [x19, #0x20]
   mov     x1, x20
   ldr     w2, [x19, #0x48]
   ldr     x3, [x0, #0x8]
   sub     x2, x24, x2
   blr     x3
   tbz     w0, #0x0, .Ltmp69

.LFT41:
   ldr     w0, [x19, #0x30]
   mov     sp, x25 // stackclash-gadget: stackclash-gadget<>
   cbz     w0, .Ltmp66

.Ltmp67:
   ldr     w0, [x19, #0x48]
   cmp     w0, #0xfff
   b.ls    .Ltmp70

.LFT42:
   mov     w0, #0x0

.Ltmp73:
   str     xzr, [x19, #0x28]
   str     xzr, [x19, #0x40]
   str     wzr, [x19, #0x48]

.Ltmp72:
   adrp    x1, #253952
   ldr     x1, [x1, #0xf98]
   ldr     x3, [x29, #0x58]
   ldr     x2, [x1]
   subs    x3, x3, x2
   mov     x2, #0x0
   b.ne    .Ltmp71

.LFT43:
   mov     sp, x29
   ldp     x19, x20, [sp, #0x10]
   ldp     x21, x22, [sp, #0x20]
   ldp     x23, x24, [sp, #0x30]
   ldr     x25, [sp, #0x40]
   ldp     x29, x30, [sp], #0x60
   autiasp
   ret

.Ltmp69:
   mov     w0, #0x0
   mov     sp, x25 // stackclash-gadget: stackclash-gadget<>
   b       .Ltmp72

.Ltmp66:
   mov     w0, #0x1
   b       .Ltmp73

.Ltmp71:
   bl      __stack_chk_fail@PLT
        .size   f , .-f


// CHECK-NOT: GS-STACKCLASH:



