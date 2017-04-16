# Convert the ROP chain to "almost" x86 code.
# Result in rop.txt
import struct

rop = {}
rop[0x806f5f0] = 'int 0x80'
rop[0x805c4a0] = 'jmp memset'
rop[0x805c660] = 'jmp memcpy'
rop[0x80489d9] = 'if eax != ebx: jmp ecx'

with open('gadgets.txt') as f:
    for l in f:
        l = l.strip()
        addr, gadget = l.split(':',1)
        gadget = gadget.strip()
        if gadget.endswith('found)'):
            gadget = ';'.join(gadget.split(';')[:-1]).strip()
        addr = int(addr, 16)
        rop[addr] = gadget

def split(r):
    gadgets = []
    for i in range(0, len(r), 4):
        w = struct.unpack('<I', r[i:i+4])[0]
        gadgets.append(w)
    return gadgets

rop_offset = 0x114
r = open('input.bin', 'r').read()[rop_offset:]
gadgets = split(r)


i = 0
targets = {}
refs = {}
while i < len(gadgets)-5:
    start = i

    a, b, c, d, e, f = gadgets[i], gadgets[i+1], gadgets[i+2], gadgets[i+3], gadgets[i+4], gadgets[i+5]
    if (a,c) == (0x80b8196, 0x809ca00):
        s = 'mov eax, [0x%08x]' % (b+4)
        i += 3
    elif a == 0x80b8196:
        s = 'mov eax, 0x%x' % b
        i += 2
    elif (a,c,d,e) == (0x8048433, 0x80489ed, 0x80489e7, 0x80489d9):
        # pop esi ; ret
        # <ESI>
        # pop ecx ; ret
        # add esp, esi ; ret
        # cmp eax, ebx ; jnz ecx ; ret
        target = (i+5)*4 + b
        s = 'cmp eax, ebx ; jnz l%08x' % target
        i += 5
        targets.setdefault(target, []).append(4*start)
    elif (a,b,c) == (0x80489ed, 0x80489e7, 0x80489d9):
        # pop ecx ; ret
        # add esp, esi ; ret
        # cmp eax, ebx ; jnz ecx ; ret
        assert 0
        s = 'if eax != ebx: add esp, esi'
        i += 3
    elif (a,b,c)==(0x08048433, 0, 0x080489e7):
        # pop esi ; ret
        # 0
        # add esp, esi ; ret
        s = 'nop'
        i += 3
    elif (a,c)==(0x08048433, 0x080489e7):
        # pop esi ; ret
        # <ESI>
        # add esp, esi ; ret
        target = (i+3)*4 + b
        s = 'jmp l%08x' % target
        targets.setdefault(target, []).append(4*start)
        i += 3
    elif (a,b,d,e) == (0x0804889e, 0x08048480, 0x080680c7, 0x44444444):
        # mov eax, esp ; ret
        # pop edi ; ret
        # <EDI>
        # add eax, edi ; pop edi ; ret
        # <garbage>
        target = (i+1)*4 + c
        s = 'mov eax, l%08x' % target
        refs.setdefault(target, []).append(4*start)
        i += 5
    elif (a,b,d,e,f) == (0x804889e, 0x8048433, 0x808e828, 0x11223344, 0x55667788):
        # mov eax, esp ; ret
        # pop esi ; ret
        # <ESI>
        # sub eax, esi ; pop esi ; pop edi ; ret
        # <garbage>
        # <garbage>
        # xchg eax, esp ; ret
        target = (i+1)*4 - c
        s = 'jmp l%08x' % target
        refs.setdefault(target, []).append(4*start)
        i += 7
    elif a == 0x804f1fc:
        s = 'mov ebx, 0x%x' % b
        i += 2
    elif a == 0x806efea:
        s ='mov edx, 0x%x' % b
        i += 2
    elif a == 0x8048480:
        s ='mov edi, 0x%x' % b
        i += 2
    elif a == 0x80680c7:
        s ='add eax, edi ; mov edi, 0x%x' % b
        i += 2
    elif a == 0x8048433:
        s ='mov esi, 0x%x' % b
        i += 2
    elif a == 0x80489ed:
        s ='mov ecx, 0x%x' % b
        i += 2
    elif a == 0x806f011:
        s ='mov ecx, 0x%x ; mov ebx, 0x%x' % (b, c)
        i += 3
    elif a == 0x808e828:
        s ='sub eax, esi ; mov esi, 0x%x ; mov edi, 0x%x' % (b, c)
        i += 3
    elif a == 0x804847e:
        s ='mov ebx, 0x%x ; mov esi, 0x%x ; mov edi, 0x%x' % (b, c, d)
        i += 4
    elif a >= 0x08040000 and a <= 0x080c0000:
        assert a in rop
        s = rop[a].strip()
        if s.endswith('; ret'):
            s = s[:-5]
        i += 1
    else:
        s = ''
        i += 1

    addr = start*4
    def get_comment(addr):
        comments = []
        for addr in targets.get(addr, []):
            comments.append('jmp from l%08x' % addr)
        for ref in refs.get(addr, []):
            comments.append('ref from l%08x' % ref)
        if comments:
            return '     # ' + ', '.join(comments)
        return ''

    print ('l%08x:  %8x  %s%s' % (addr, gadgets[start], s, get_comment(start*4))).strip()
    for j in range(start+1, i):
        print '            %8x%s' % (gadgets[j], get_comment(j*4))
