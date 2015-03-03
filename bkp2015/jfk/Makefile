cc = arm-linux-gnueabi-gcc
cflags = -nostdlib -Os

all: pwn

libc.o: libc.S libc.c
	$(cc) $(cflags) -r -o libc.o libc.S libc.c

pwn: pwn.c libc.o
	$(cc) $(cflags) -o pwn pwn.c libc.o
