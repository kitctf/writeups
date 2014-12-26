import random
 
f = open("wtfregexp.pl", "r")
reg = f.readlines()[0]
reg = reg[reg.index('/')+1:-3]
 
clauses = []
maxi = 0
for l in reg.split(','):
    l = l[3:-1].replace("[01]", ".")
    if '(' not in l: continue
    front = 0
    end = 0
    while l[front] == '.':
        front += 1
    a = int(l[l.index("(")+3])
    b = int(l[l.index(")")-1])
    mid = l.index("|") - l.index("(") - 4
    while l[len(l)-end-1] == '.':
        end += 1
    v1 = front+1
    v2 = front+mid+1
    if not a: v1 = -v1
    if not b: v2 = -v2
    clauses.append((v1, v2))
 
# string has to start with 01
clauses.append((-1, -1))
clauses.append((2, 2))
 
# Papadimitriou's random walk algorithm for 2-SAT:
# 1. Pick any assignment of variables
# 2. While there are unfulfilled clauses
#     2.1 pick one of them at random
#     2.2 pick one of the variables of the clause at random
#     2.3 flip the value for that variable
#
# Polynomial runtime with high probability (O(n^2 * m)) here
 
s = ["0"]*256
def fulfilled(v):
    return v > 0 and s[v-1] == '1' or v < 0 and s[-v-1] == '0'
while 1:
    wrong = []
    for a, b in clauses:
        if not fulfilled(a) and not fulfilled(b):
            wrong += [a,b]
    if not wrong:
        break
    fix = random.choice(wrong)
    if fix > 0:
        s[fix-1] = '1'
    else:
        s[-fix-1] = '0'
    assert fulfilled(fix)
print "".join(chr(int("".join(s[i*8:i*8+8]),2)) for i in xrange(len(s)/8))
