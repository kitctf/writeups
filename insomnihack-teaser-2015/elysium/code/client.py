#!/usr/bin/env python3
#coding: UTF-8

from elysium import *

TARGET = ('elysium01.teaser.insomnihack.ch', 1234)

with connect(TARGET) as c:
    iv = c.recv(16)
    client = Client(c, iv)
    client.interact()
