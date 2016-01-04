shellcode: shellcode.asm
	nasm -f elf64 shellcode.asm
	objcopy -O binary shellcode.o shellcode
	rm shellcode.o

readloop: readloop.asm
	nasm -f elf64 readloop.asm
	objcopy -O binary readloop.o shellcode
	rm readloop.o

clean:
	rm shellcode
	rm readloop
