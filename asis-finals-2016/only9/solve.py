#!/usr/bin/env python
#
# Pick an index i and 256 plaintexts P_k that all differ in byte i, but coincide in
# all indexes j != i. Then after 8 rounds, the i-th byte of the XOR of all
# ciphertexts C_k of P_k is 0. We can use this to mount a square attack:
#
# The final ciphers after 9 rounds are C'_k = M*(SBOX(C_k)) ^ K where K is the
# last round key. This can be rewritten as C_k = SBOX^-1((M^-1 * C'_k) ^ (M^-1 * K))
# We can use the characteristic from above to brute force the i-th byte of
# M^-1 * K. Do this for all i to get K completely. Then reconstruct the original
# key from it by reversing the key schedule.

import os, sys, hashlib, random, socket

N = 16
M = 8
KEY_CONST = [0xde, 0xad, 0xbe, 0xee, 0xef, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0xfc, 0xaa, 0xbb, 0xcc, 0xdd]
NROUNDS = 9
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

matrix = [
    [1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0],
    [0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0],
    [1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0],
    [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
]

matrix_rev = [
    [1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1],
    [1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1],
    [1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1],
    [1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1],
    [1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1],
    [0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0],
    [1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0],
    [1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1],
    [0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0],
    [0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0],
    [1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1],
    [1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1],
    [1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1],
    [0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0],
    [1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1],
    [0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1],
]

def add_key(s, k):
    return [x ^ y for x, y in zip(s, k)]

def apply_matrix(s, matrix):
    s2 = [0] * N
    for y, row in enumerate(matrix):
        for x, take in enumerate(row):
            if take:
                s2[y] ^= s[x]
    return s2

def stoh(s):
    assert len(s) == 16
    return "".join("%02x" % v for v in s)

def htos(h):
    try:
        res = map(ord, h.decode("hex"))
        assert len(res) == 16
        return res
    except:
        assert 0


#############################

SBOX_REV = [0]*256
for i, x in enumerate(SBOX):
    SBOX_REV[x] = i

def r_lin(s):
    return apply_matrix(s, matrix_rev)

def r_schedule(k, rounds):
    for r in xrange(rounds - 1, -1, -1):
        k = add_key(k, [SBOX[r]] * N)
        k = add_key(k, KEY_CONST)
        k = r_lin(k)
    return k

def encrypt(s, k):
    s = add_key(s, k)
    for r in xrange(NROUNDS):
        k = apply_matrix(k, matrix)
        k = add_key(k, KEY_CONST)
        k = add_key(k, [SBOX[r]] * N)

        s = [SBOX[y] for y in s]
        s = apply_matrix(s, matrix)
        s = add_key(s, k)
    return s

def decrypt(s, k):
    keys = [k]
    for r in xrange(NROUNDS):
        k = apply_matrix(k, matrix)
        k = add_key(k, KEY_CONST)
        k = add_key(k, [SBOX[r]] * N)
        keys.append(k)

    for r in xrange(NROUNDS - 1, -1, -1):
        s = add_key(s, keys[r + 1])
        s = r_lin(s)
        s = [SBOX_REV[y] for y in s]

    s = add_key(s, keys[0])
    return s

def randseq(n):
    return [random.randrange(256) for _ in xrange(n)]

def solve(oracle):
    key = []
    for i in range(N):
        print 'Finding key byte @', i
        candidates = set(range(256))
        while len(candidates) > 1:
            print '  %d candidates left, filtering' % len(candidates)
            prefix = randseq(i)
            suffix = randseq(16-i-1)
            # generate set with active byte at position i
            plains = [prefix + [x] + suffix for x in range(256)]
            # use oracle to compute relevant bytes of M^-1 * C'
            ciphers = []
            for j, p in enumerate(plains):
                if j % 30 == 0: print '   ', j
                ciphers.append(r_lin(oracle(p))[i])
            cand = set()
            # brute force i-th byte of M^-1 * K
            for x in range(256):
                pre = 0
                for c in ciphers:
                    pre ^= SBOX_REV[c ^ x]
                if pre == 0: cand.add(x)
            candidates &= cand
        key.append(list(candidates)[0])

    # reverse key schedule to get the final key
    return r_schedule(apply_matrix(key, matrix), 9)

TARGET = ('only9.asis-ctf.ir', 42953)
#TARGET = ('localhost', 6666)

s = socket.create_connection(TARGET)

def ru(st):
    buf = ''
    while not st in buf:
        c = s.recv(1)
        assert c
        buf += c
    return buf

ru('flag: ')
enc_flag = htos(ru('\n')[:-1])
ru('---\n')

def oracle(plain):
    s.send(stoh(plain) + '\n')
    ru('=> ')
    return htos(ru('\n')[:-1])

key = solve(oracle)
print ''.join(map(chr, decrypt(enc_flag, key)))
