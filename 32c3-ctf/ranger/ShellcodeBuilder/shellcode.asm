section .text
        mov rsi, 0x602650
        mov rsi, QWORD [rsi]

        mov rdx, 0x300
        mov rdi, 5
        mov rax, 1
        syscall

exit:
        xor rdi, rdi
        mov rax, 60
        syscall                     ; exit
