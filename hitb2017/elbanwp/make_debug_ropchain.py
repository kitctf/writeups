import struct

def p(x):
    return struct.pack('<I', x)

rop = open('input.bin').read()

def fix(rop, pattern, subst):
    pattern = ''.join(pattern)
    subst = ''.join(subst)
    assert rop.count(pattern) == 1, str(rop.count(pattern))
    return rop.replace(pattern, subst)

def xor(a, b):
    return ''.join(chr(ord(x)^ord(y)) for x, y in zip(a,b))

def insert(rop, i, s):
    return rop[:i] + s + rop[i+len(s):]

def insert_xor(rop, i, s):
    return rop[:i] + xor(rop[i:i+len(s)], s) + rop[i+len(s):]

# replace exit(666) by crash at 0x13371337 for opcode 0xff
pattern = [
    p(0x806efea),
    p(0),
    p(0x80b8196),
    p(1),
    p(0x806f5f0),
    p(0x8048433),
]

subst = [
    p(0x806efea),
    p(0),
    p(0x80b8196),
    p(1),
    p(0x13371337),
    p(0x8048433),
]

rop_offset = 0x114
stage1_offset = rop_offset + 0x1f04
stage2_offset = stage1_offset + 0x5df

rop = fix(rop, pattern, subst)

# patch out nanosleep
rop = insert(rop, stage1_offset + 0x158, '\x00\x00\x11\xa3')

# example: break at encrypt in stage2
rop = insert_xor(rop, stage2_offset + 0x128, xor('\0\0\0\xf2', '\0\0\0\xff'))

with open('input_debug.bin', 'w') as f:
    f.write(rop)
