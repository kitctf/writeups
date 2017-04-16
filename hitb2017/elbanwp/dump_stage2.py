import string
import sys

alph = ''.join(map(chr, range(20, 128)))

rop = open('input.bin', 'r').read()
code = rop[0x114+0x1f04:]
xorstr = code[0x5df:]

key = 'd1m1tr1z'
assert sum(ord(x) for x in key) == 708

def xor(a, key):
    while len(key) < len(a):
        key = key + key
    return ''.join(chr(ord(x)^ord(y)^0xaa) for x, y in zip(a, key))

def hexdump(x):
    for i in range(min(len(x),100)):
        sys.stdout.write( hex(ord(x[i]))[2:] + ' ')
    print

# find candidates for key positions 3 and 7 by comparing XOR values with opcodes
opcodes = [160, 161, 162, 163, 176, 192, 193, 194, 195, 208, 209, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 240, 241, 242, 243, 255]

hexdump(xorstr)
hexdump(xor(xorstr, key))

for a in range(0x100):
    for i in range(3 ,200, 8):
        if ord(xorstr[i])^a^0xaa not in opcodes:
            break
    else:
        print "key[3] =", chr(a)

for a in range(0x100):
    for i in range(7 ,200, 8):
        if ord(xorstr[i])^a^0xaa not in opcodes:
            break
    else:
        print "key[7] =", chr(a)

with open('stage2.bin', 'w') as f:
    f.write(xor(xorstr, key))
