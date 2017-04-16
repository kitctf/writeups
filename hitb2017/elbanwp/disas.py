import sys

def r(x):
    special = {
        11: 'bp',
        12: 'sp',
        13: 'lr',
        14: 'pc',
    }
    if x in special:
        return special[x]
    return 'r%d'%x

def op_a0(a1,a2,a3,b1):
    if a1 & 0x10:
        a1 &= 0xf
        return 'mov %s, %s + 0x%x' % (r(a1), r(a1), b1)
    else:
        return 'mov %s, %s + %s' % (r(a1), r(a1), r(a2))

def op_a1(a1,a2,a3,b1):
    if a1 & 0x10:
        a1 &= 0xf
        return 'mov %s, %s - 0x%x' % (r(a1), r(a1), b1)
    else:
        return 'mov %s, %s - %s' % (r(a1), r(a1), r(a2))

def op_a2(a1,a2,a3,b1):
    if a1 & 0x10:
        a1 &= 0xf
        return 'mov %s, %s ^ 0x%x' % (r(a1), r(a1), b1)
    else:
        return 'mov %s, %s ^ %s' % (r(a1), r(a1), r(a2))

def op_a3(a1,a2,a3,b1):
    if a1 & 0x10:
        a1 &= 0xf
        return 'mov %s, 0x%x' % (r(a1), b1)
    else:
        return 'mov %s, %s' % (r(a1), r(a2))

def op_b0(a1,a2,a3,b1):
    if a1 & 0x10:
        a1 &= 0xf
        return 'cmp %s, 0x%x' % (r(a1), b1)
    else:
        return 'cmp %s, %s' % (r(a1), r(a2))

def op_c0(a1,a2,a3,b1):
    return 'jeq 0x%04x' % b1

def op_c1(a1,a2,a3,b1):
    return 'jne 0x%04x' % b1

def op_c2(a1,a2,a3,b1):
    return 'jmp 0x%04x' % b1

def op_c3(a1,a2,a3,b1):
    return 'call 0x%04x' % b1

def op_d0(a1,a2,a3,b1):
    return 'ret'

def op_d1(a1,a2,a3,b1):
    return 'syscall %d' % b1

def op_e0(a1,a2,a3,b1):
    return 'mov %s, dword [%s + %s]' % (r(a1), r(a2), r(a3))
def op_e4(a1,a2,a3,b1):
    return 'mov %s, word [%s + %s]' % (r(a1), r(a2), r(a3))
def op_e8(a1,a2,a3,b1):
    return 'mov %s, byte [%s + %s]' % (r(a1), r(a2), r(a3))

def op_e1(a1,a2,a3,b1):
    return 'mov %s, dword [%s + 0x%x]' % (r(a1>>4), r(a1&0xf), b1)
def op_e5(a1,a2,a3,b1):
    return 'mov %s, word [%s + 0x%x]' % (r(a1>>4), r(a1&0xf), b1)
def op_e9(a1,a2,a3,b1):
    return 'mov %s, byte [%s + 0x%x]' % (r(a1>>4), r(a1&0xf), b1)

def op_e2(a1,a2,a3,b1):
    return 'mov dword [%s + %s], %s' % (r(a2), r(a3), r(a1))
def op_e6(a1,a2,a3,b1):
    return 'mov word [%s + %s], %s' % (r(a2), r(a3), r(a1))
def op_ea(a1,a2,a3,b1):
    return 'mov byte [%s + %s], %s' % (r(a2), r(a3), r(a1))

def op_e3(a1,a2,a3,b1):
    return 'mov dword [%s + 0x%x], %s' % (r(a1&0xf), b1, r(a1>>4))
def op_e7(a1,a2,a3,b1):
    return 'mov word [%s + 0x%x], %s' % (r(a1&0xf), b1, r(a1>>4))
def op_eb(a1,a2,a3,b1):
    return 'mov byte [%s + 0x%x], %s' % (r(a1&0xf), b1, r(a1>>4))

def op_f0(a1,a2,a3,b1):
    return 'shl %s, 0x%x' % (r(a1), b1)
def op_f1(a1,a2,a3,b1):
    return 'shr %s, 0x%x' % (r(a1), b1)

def op_f2(a1,a2,a3,b1):
    return 'push %s' % r(a1)
def op_f3(a1,a2,a3,b1):
    return 'pop %s' % r(a1)

def op_ff(a1,a2,a3,b1):
    return 'halt'

# print "opcodes =",[int(name[3:],16) for name in dir() if name.startswith('op_')]

def disas(insn):
    opcode = ord(insn[3])
    a1 = ord(insn[2])
    a2 = ord(insn[1])
    a3 = ord(insn[0])
    b1 = (a2 << 8) | a3
    try:
        f = eval('op_%02x' % opcode)
    except NameError:
        return '<unknown>'
    return f(a1,a2,a3,b1)

code = open(sys.argv[1]).read()
offset = 0
if len(sys.argv) > 2:
    offset = int(sys.argv[2],16)

def strlit(offset):
    res = ''
    while code[offset] != '\0':
        res += code[offset]
        offset+=1
    return res

# print strlit(0x77a)
# print strlit(0x2d1)
# print repr(code[0x7b4:0x7b4+8])
# exit()

for i in range(0, len(code), 4):
    if i + 4 >= len(code):
        break
    prefix = '%08x    ' % (offset+i)
    for j in range(4):
        prefix += '%02x ' % ord(code[i+j])
    prefix += '     '
    print prefix + disas(code[i:i+4])
