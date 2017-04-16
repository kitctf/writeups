# processor module for IDA
# adapted from https://github.com/cregnec/ida-processor-script/blob/master/ida-proc.py
from idaapi import *

class DecodingError(Exception):
    pass

class MyProcessor(processor_t):
    id = 0x8000 + 8888
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["blasty"]
    plnames = ["BLASTY VM HITB2017AMS"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "My assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = [
        "r0", "r1", "r2", "r3", "r4",
        "r5", "r6", "r7", "r8", "r9",
        "r10", "bp", "sp", "lr",
        "ip",
        #virtual
        "cs", "ds"
    ]

    instruc = instrs = [
        { 'name': 'add', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'sub', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'xor', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'mov', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'cmp', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'je', 'feature': CF_USE1 },
        { 'name': 'jne', 'feature': CF_USE1 },
        { 'name': 'jmp', 'feature': CF_USE1 },
        { 'name': 'call', 'feature': CF_USE1 | CF_CALL },
        { 'name': 'ret', 'feature': CF_STOP },
        { 'name': 'syscall', 'feature': CF_USE1 },
        { 'name': 'ld', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'st', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'shl', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'shr', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'push', 'feature': CF_USE1 },
        { 'name': 'pop', 'feature': CF_USE1 },
        { 'name': 'halt', 'feature': CF_STOP },
    ]
    instruc_end = len(instruc)

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["cs"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["ds"]

    def _ana_jmp(self, name):
        cmd = self.cmd
        cmd.itype = self.inames[name]
        cmd[0].type = o_near
        cmd[0].dtyp = dt_dword
        cmd[0].addr = self.b1

    def _ana_arith(self, name):
        cmd = self.cmd
        cmd.itype = self.inames[name]
        cmd[0].type = o_reg
        cmd[0].dtyp = dt_dword
        cmd[0].reg = self.a1 & 0xf
        if self.a1 & 0x10:
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_dword
            cmd[1].value = self.b1
        else:
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_dword
            cmd[1].reg = self.a2

    def _ana(self):
        cmd = self.cmd
        cmd.size = 4

        opcode = get_full_byte(cmd.ea + 3)
        self.a1 = get_full_byte(cmd.ea + 2)
        self.a2 = get_full_byte(cmd.ea + 1)
        self.a3 = get_full_byte(cmd.ea + 0)
        self.b1 = (self.a2 << 8) | self.a3

        if opcode == 0xa0:
            self._ana_arith('add')
        elif opcode == 0xa1:
            self._ana_arith('sub')
        elif opcode == 0xa2:
            self._ana_arith('xor')
        elif opcode == 0xa3:
            self._ana_arith('mov')
        elif opcode == 0xb0:
            self._ana_arith('cmp')

        elif opcode == 0xc0:
            self._ana_jmp('je')
        elif opcode == 0xc1:
            self._ana_jmp('jne')
        elif opcode == 0xc2:
            self._ana_jmp('jmp')
        elif opcode == 0xc3:
            self._ana_jmp('call')

        elif opcode == 0xd0:
            cmd.itype = self.inames['ret']

        elif opcode == 0xd1:
            cmd.itype = self.inames['syscall']
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_dword
            cmd[0].value = self.b1

        elif opcode in (0xe0, 0xe4, 0xe8):
            cmd.itype = self.inames['ld']
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_dword
            cmd[0].reg = self.a1
            cmd[1].type = o_phrase
            cmd[1].dtyp = [dt_dword, dt_word, dt_byte][(opcode - 0xe0)//4]
            cmd[1].phrase = self.a2
            cmd[1].specval = self.a3

        elif opcode in (0xe1, 0xe5, 0xe9):
            cmd.itype = self.inames['ld']
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_dword
            cmd[0].reg = self.a1>>4
            cmd[1].type = o_displ
            cmd[1].dtyp = [dt_dword, dt_word, dt_byte][(opcode - 0xe1)//4]
            cmd[1].phrase = self.a1&0xf
            cmd[1].addr = self.b1

        elif opcode in (0xe2, 0xe6, 0xea):
            cmd.itype = self.inames['st']
            cmd[0].type = o_phrase
            cmd[0].dtyp = [dt_dword, dt_word, dt_byte][(opcode - 0xe2)//4]
            cmd[0].phrase = self.a2
            cmd[0].specval = self.a3
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_dword
            cmd[1].reg = self.a1

        elif opcode in (0xe3, 0xe7, 0xeb):
            cmd.itype = self.inames['st']
            cmd[0].type = o_displ
            cmd[0].dtyp = [dt_dword, dt_word, dt_byte][(opcode - 0xe3)//4]
            cmd[0].phrase = self.a1 & 0xf
            cmd[0].addr = self.b1
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_dword
            cmd[1].reg = self.a1 >> 4

        elif opcode in (0xf0, 0xf1):
            cmd.itype = self.inames[{0xf0: 'shl', 0xf1: 'shr'}[opcode]]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_dword
            cmd[0].reg = self.a1
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_dword
            cmd[1].value = self.b1

        elif opcode in (0xf2, 0xf3):
            cmd.itype = self.inames[{0xf2: 'push', 0xf3: 'pop'}[opcode]]
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_dword
            cmd[0].reg = self.a1

        elif opcode == 0xff:
            cmd.itype = self.inames['halt']

        # print "Cmd"
        # print "  itype = ", cmd.itype
        # print "  size = ", cmd.size
        # print "  op0 = ", cmd[0].type
        # print "  op1 = ", cmd[1].type
        # print cmd.itype

        return cmd.size

    def ana(self):
        try:
            return self._ana()
        except DecodingError:
            return 0

    def _emu_operand(self, op):
        if op.type == o_mem:
            ua_dodata2(0, op.addr, op.dtyp)
            ua_add_dref(0, op.addr, dr_R)
        elif op.type == o_near:
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(0, op.addr, fl)

    def emu(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(cmd[0])
        if ft & CF_USE2:
            self._emu_operand(cmd[1])
        if ft & CF_USE3:
            self._emu_operand(cmd[2])
        if not ft & CF_STOP:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)
        return True

    def outop(self, op):
        if op.type == o_reg:
            out_register(self.reg_names[op.reg])
        elif op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type in [o_near, o_mem]:
            ok = out_name_expr(op, op.addr, BADADDR)
            if not ok:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, self.cmd.ea)
        elif op.type == o_phrase:
            out_keyword({dt_dword: 'dword', dt_word: 'word', dt_byte: 'byte'}[op.dtyp])
            OutLine(' ')
            out_symbol('[')
            out_register(self.reg_names[op.phrase])
            OutLine(' ')
            out_symbol('+')
            OutLine(' ')
            out_register(self.reg_names[op.specval])
            out_symbol(']')
        elif op.type == o_displ:
            out_keyword({dt_dword: 'dword', dt_word: 'word', dt_byte: 'byte'}[op.dtyp])
            OutLine(' ')
            out_symbol('[')
            out_register(self.reg_names[op.phrase])
            if op.addr:
                OutLine(' ')
                out_symbol('+')
                OutLine(' ')
                OutLong(op.addr, 16)
            out_symbol(']')
        else:
            return False
        return True

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        OutMnem(15)
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

def PROCESSOR_ENTRY():
    return MyProcessor()
