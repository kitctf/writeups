// who needs a real libc anyways?

.global open
.global write
.global close
.global execve
.global getuid

.text

syscall:
    svc 0
    pop {r7}
    bx lr

open:
    push {r7}
    mov r7, #5
    b syscall

write:
    push {r7}
    mov r7, #4
    b syscall

close:
    push {r7}
    mov r7, #6
    b syscall

execve:
    push {r7}
    mov r7, #11
    b syscall

getuid:
    push {r7}
    mov r7, #24
    b syscall

