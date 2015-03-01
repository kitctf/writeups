from base64 import *
import hashlib
import random
import socket
import sys
import time

p = 27327395392065156535295708986786204851079528837723780510136102615658941290873291366333982291142196119880072569148310240613294525601423086385684539987530041685746722802143397156977196536022078345249162977312837555444840885304704497622243160036344118163834102383664729922544598824748665205987742128842266020644318535398158529231670365533130718559364239513376190580331938323739895791648429804489417000105677817248741446184689828512402512984453866089594767267742663452532505964888865617589849683809416805726974349474427978691740833753326962760114744967093652541808999389773346317294473742439510326811300031080582618145727L

def ex_gcd(a, b):
    x1 = 0; y1 = 1
    x = 1; y = 0
    while b:
        q = a / b; r = a % b
        x2 = x - q * x1; y2 = y - q * y1
        a = b; b = r; x = x1; x1 = x2; y = y1; y1 = y2
    return a, x, y

def root2(y, p):
    """ Solve x^2 == y (mod p) """
    assert p % 4 == 3
    x = pow(y, (p+1)/4, p)
    assert pow(x, 2, p) == y
    return x

def root(n, y, p):
    """ Solve x^n == y (mod p) """
    g, u, _ = ex_gcd(n, p-1)
    if g == 2:
        return root(n/2, root2(y, p), p)
    assert g == 1
    u %= p-1
    x = pow(y, u, p)
    assert pow(x, n, p) == y
    return x

SERVER = 'bostonkeyparty.net'
PORT = 1025

s = socket.create_connection((SERVER, PORT))

pref = s.recv(4096)
assert len(pref) == 12
print "Solving challenge %s" % pref
i = 0
while True:
    answer = pref + ''.join(chr(random.randint(0,0xff)) for _ in xrange(8))
    assert len(answer) == 20
    ha = hashlib.sha1()
    ha.update(answer)
    if ha.digest().endswith('\xff\xff\xff'):
        break
    i += 1
    if i % 100000 == 0:
        print i
print "Done!"
s.send(answer)

def oracle(b):
    """ Let the server compute b^s mod p. If the result is 4, print
    the flag. Otherwise, return the result and the timing. """
    t0 = time.time()
    s.send(str(b) + '\n')
    ans = s.recv(4096)
    t = time.time() - t0
    if any(c not in "0123456789" for c in ans):
        print ans
        sys.exit(0)
    return int(ans), t

prefix = 1
while True:
    prefix <<= 1
    # check the two possible hypotheses on the extension of s
    _, a = oracle(root(prefix | 0, 4, p))
    _, b = oracle(root(prefix | 1, 4, p))
    print bin(prefix>>1), a, b
    # no difference in timing, we are at the last bit
    if abs(a - b) < 0.5:
        break
    if b > a:
        # the version with an appended 1 bit took longer, so it is the correct guess
        prefix |= 1

# there are two possible options for the last bit, check them using the
# exponentiation oracle
for c in (prefix | 0, prefix | 1):
    if oracle(13)[0] == pow(13, c, p):
        s = c
        break
else:
    # something went wrong
    assert 0

# send the final guess and get the flag
oracle(root(s, 4, p))
