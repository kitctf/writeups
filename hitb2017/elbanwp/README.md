# HITB 2017 - BIN400 - Elbanwp

This was a brutal reversing challenge. A VM for a custom(?) architecture was
implemented as a ROP chain and we had to reverse it to even be able to disassemble
the logic parsing the input. There was a second stage too which was basically a
normal crackme, using the custom arch.


## Tools

### dump_ropchain.py

Parses the ROP chain and outputs it in an x86-like format for reversing. The
output (which I commented while reversing it) is in the file rop.txt.
The VM is implemented as a main loop which parses the next instruction and
then sequentially compares the opcode to all possible values, essentially
implementing a large switch statement.

### vm_notes.txt

This contains my notes about how the VM works, where it stores the registers
and how the instructions work.

### dump_stage1.py

Dumps the first stage of VM code from the ROP chain into the file stage1.bin.

### disas.py

Disassembles a file containing code for the VM. The commented disassembly for
stage1 and stage2 are in stage1_disas.txt and stage2_disas.txt.

### dump_stage2.py

This was used to figure out the key for stage1 and to decrypt stage2. It dumps
the second stage into stage2.bin.

### brute_stage2.cpp

This C++ file brute forces the key for stage2.

### make_debug_ropchain.py

Used to modify the original ROP chain for "debugging". exit(666) is replaced
with a crash at 0x13371337, nanosleep is patched out and we can crash
at arbitrary locations in stage1 or stage2.
