.section .text
.global _start

_start:
    adr     r0, fname
    mov     r1, #0

    mov     r7, #5
    svc     0x0
    mov     r6, r0

    mov     r1, sp
    mov     r2, #0x80
    mov     r7, #3
    svc     0x0

    mov     r0, #1
    mov     r7, #4
    svc     0x0

    mov     r7, #1
    svc     0x0

.align 4
fname:
    .byte 47, 102, 108, 97, 103, 0
