import random
import struct
import socket
import sys

def read_until(s, f):
    if not callable(f):
        f = lambda s, st=f: st in s
    buf = ''
    while not f(buf):
        c = s.recv(1)
        assert c
        buf += c
    return buf

sock = socket.create_connection(('localhost', 8888))
read_until(sock, 'Please decrypt: ')
secret_cipher = read_until(sock, '\n')[:-1]
print >>sys.stderr, '[*] Secret =', secret_cipher

def oracle(s):
    sock.sendall(''.join(map(chr, s)))
    resp = read_until(sock, '\n')[:-1]
    return map(ord, resp.decode('hex'))

def list_xor(a,b):
    return [x^y for x, y in zip(a,b)]

diffs = [
    # todo fix round 1
    ([1, 2, 3, 4, 5, 6, 7, 8],
        [1, 2, 3, 4]),
    ([0x80, 0x80, 0, 0, 0x80, 0x80, 0, 4],
        [0, 0, 0, 4]),
    ([0, 0, 0, 0, 0x80, 0x80, 0, 0],
        [0, 0, 0, 4]),
    ([0x80, 0x80, 0, 0, 0x80, 0x80, 0, 0],
        [0, 0, 0, 4]),
]

random.seed(1)
N = 15
print N
cnt=0
for r, (diff, check) in enumerate(diffs):
    #if cnt == 3:
        #DEBUG = True
    #else: DEBUG = False
    for _ in range(N):
        cnt += 1
        x0 = [random.randint(0,0xff) for _ in range(8)]
        if r == 0:
            x1 = [random.randint(0,0xff) for _ in range(8)]
            check2 = list_xor(x0, x1)[:4]
        else:
            x1 = list_xor(x0, diff)
            check2 = check
        print ' '.join(map(str, x0))
        print ' '.join(map(str, x1))
        print ' '.join(map(str, oracle(x0)))
        print ' '.join(map(str, oracle(x1)))
        print ' '.join(map(str, check2))

# send the output of this program to crack.cpp to recover subkeys
