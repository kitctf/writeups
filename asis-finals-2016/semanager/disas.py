import sys
import struct
import re

f = open(sys.argv[1]).read()

magic, filesz, code_offset, data_offset, code_size, data_size = \
  struct.unpack('<IIIIII', f[:4*6])

code = f[code_offset:code_offset + code_size]
data = f[data_offset:data_offset + data_size]

print "filesz = %08x" % filesz
print "code_offset = %08x" % code_offset
print "data_offset = %08x" % data_offset
print "code_size = %08x" % code_size
print "data_size = %08x" % data_size
print '===================='
print 'data = %s' % repr(data)
print '===================='

code_addr = 0x1000
data_addr = 0x2000

def reg(i):
    if 0 <= i < 8:
        #return 'r%d' % i
        return ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r13', 'r14'][i]
        #return 'r%d' % i
    else:
        return {8:'rip', 9:'rsp', 10:'rbp', 11:'flags', 12:'r12'}[i]

def mov_ops(code, i):
    _, optype, opsize = struct.unpack('<BBB', code[i:i+3])

    if optype & 0xf0 == 0:
        op1, = struct.unpack('<B', code[i+3:i+4])
        offset = 1
        lhs = reg(op1)
    elif optype & 0xf0 == 0x10:
        op1, = struct.unpack('<B', code[i+3:i+4])
        offset = 1
        lhs = '[%s]' % reg(op1)
    elif optype & 0xf0 == 0x20:
        op1, = struct.unpack('<I', code[i+3:i+7])
        offset = 5
        lhs = '[0x%x]' % op1
    else:
        assert 0

    if optype & 0xf == 0:
        op2, = struct.unpack('<B', code[i+3+offset:i+3+offset+1])
        rhs = reg(op2)
        offset += 1
    elif optype & 0xf == 1:
        op2, = struct.unpack('<B', code[i+3+offset:i+3+offset+1])
        rhs = '[%s]' % reg(op2)
        offset += 1
    elif optype & 0xf == 2:
        op2, = struct.unpack('<I', code[i+3+offset:i+3+offset+4])
        rhs = '[0x%x]' % op2
        offset += 4
    elif optype & 0xf == 4:
        op2, = struct.unpack('<I', code[i+3+offset:i+3+offset+4])
        rhs = '0x%x' % op2
        offset += 4
    else:
        assert 0

    assert offset == opsize

    return '%s, %s' % (lhs, rhs)

def jmp_ops(code, i):
    _, optype, opsize = struct.unpack('<BBB', code[i:i+3])
    if optype:
        op, = struct.unpack('<i', code[i+3:i+7])
        assert opsize == 4
        return 'loc_0x%x' % (code_addr + i + op)
    else:
        op, = struct.unpack('<B', code[i+3:i+4])
        assert opsize == 1
        return '%s' % reg(op)

def decode(code, i):
    opcode, optype, opsize = struct.unpack('<BBB', code[i:i+3])
    mnem = 'unknown insn: %d' % opcode
    if opcode == 0:
        mnem = 'mov %s' % mov_ops(code, i)
    elif opcode == 1:
        mnem = 'add %s' % mov_ops(code, i)
    elif opcode == 2:
        mnem = 'sub %s' % mov_ops(code, i)
    elif opcode == 3:
        mnem = 'call %s' % jmp_ops(code, i)
    elif opcode == 4:
        if optype:
            op1, op2 = struct.unpack('<BI', code[i+3:i+8])
            assert opsize == 5
            mnem = 'cmp %s, 0x%x' % (reg(op1), op2)
        else:
            op1, op2 = struct.unpack('<BB', code[i+3:i+5])
            assert opsize == 2
            mnem = 'cmp %s, %s' % (reg(op1), reg(op2))
    elif opcode == 5:
        mnem = 'jmp %s' % jmp_ops(code, i)
    elif opcode == 6:
        mnem = 'jeq %s' % jmp_ops(code, i)
    elif opcode == 7:
        mnem = 'jne %s' % jmp_ops(code, i)
    elif opcode == 8:
        mnem = 'jg %s' % jmp_ops(code, i)
    elif opcode == 9:
        mnem = 'jl %s' % jmp_ops(code, i)
    elif opcode == 10:
        if optype:
            op, = struct.unpack('<I', code[i+3:i+7])
            assert opsize == 4
            mnem = 'push 0x%x' % op
        else:
            op, = struct.unpack('<B', code[i+3:i+4])
            assert opsize == 1
            mnem = 'push %s' % reg(op)
    elif opcode == 11:
        op, = struct.unpack('<B', code[i+3:i+4])
        assert opsize == 1
        mnem = 'pop %s' % reg(op)
    elif opcode == 12:
        mnem = 'xor %s' % mov_ops(code, i)
    elif opcode == 13:
        mnem = 'syscall'
    elif opcode == 14:
        mnem = 'ret'
    #else:
        #assert 0

    return i + 3 + opsize, mnem

insns = []
labels = set()

i = 0
while i < len(code):
    next_i, insn = decode(code, i)
    insns.append((code_addr + i, insn))
    for label in re.findall(r'loc_0x[a-z0-9A-Z]+', insn):
        labels.add(label)
    #print '%08x: %s' % (code_addr + i, insn)
    i = next_i

assert i == code_size

#print 'BITS 64'
print 'entry:'
for addr, insn in insns:
    label = 'loc_0x%x' % addr
    if label in labels:
        print '%s:' % label
    print '  %s  ; 0x%x' % (insn, addr)
