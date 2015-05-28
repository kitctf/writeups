import random
from flag import FLAG

def generate_40_bytes_random_number():
   return int(open('/dev/urandom').read(80).encode('hex'), 16)

def generate_random_number_bytes(n):
   res = 0
   while res < 2**(8*n):
     res += generate_40_bytes_random_number()
     res *= 2**(40*8)
   return res

def gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)

def check_prime(p):
    """Miller-Rabin test"""
    if p & 1 == 0:
        return False
    m = p - 1
    s = 0
    while m & 1 == 0:
        m >>= 1
        s += 1
    for j in range(100):
        a = generate_40_bytes_random_number()
        if gcd(a, p) != 1:
            return False
        b = pow(a, m * (1 << s), p)
        if b in (0, 1, p - 1):
            continue
        for i in range(s):
            b = pow(b, 2, p)
            if b == 1:
                return False
            if b == p - 1:
                if i < s - 1:
                    break
                else:
                    return False
        else:
            return False
    return True

def get_prime(n):
  while (not check_prime(n)) or (((n-1) % 3) == 0):
    n += random.getrandbits(512)
  return n

r = generate_random_number_bytes(1024)
p = get_prime(r % (2**512))
q = get_prime((r >> 512) % (2**512))

n = p*q

open('out/n1','w').write(str(n))
e=3

flag_index = random.getrandbits(10)

for i in range(0, 1024):
   if i <> flag_index:
     encryptedFlag = pow(FLAG * 2**32 + random.getrandbits(32), e, n)
     open('out/flag'+str(i),'w').write(str(encryptedFlag))
r = generate_random_number_bytes(1024)
p = get_prime(r % (2**512))
q = get_prime((r >> 512) % (2**512))

n = p*q

open('out/n2','w').write(str(n))
e=3

encryptedFlag = pow(FLAG, e, n)
open('out/flag'+str(flag_index),'w').write(str(encryptedFlag))


