#!/usr/bin/python

import socket
import struct
import sys

TYPE_ADDFUNC = 0
TYPE_VERIFY = 1
TYPE_RUNFUNC = 2

OP_ADD = 0
OP_BR = 1
OP_BEQ = 2
OP_BGT = 3
OP_MOV = 4
OP_OUT = 5
OP_EXIT = 6

def createOperation(op, opnd1, opnd2, opnd3):
    operation = struct.pack("H", op)
    operation += struct.pack("Q", opnd1)
    operation += struct.pack("Q", opnd2)
    operation += struct.pack("Q", opnd3)
    return operation

def createFunction(num_ops, num_args, bytecode):
    function = struct.pack("H", num_ops)
    function += struct.pack("H", num_args)
    function += struct.pack("B", 0)
    function += bytecode
    return function

def addFunction(sockfd, function):
    packet = struct.pack("B", TYPE_ADDFUNC)
    packet += struct.pack("H", len(function))
    packet += function
    sockfd.send(packet)
    sockfd.recv(2)
    if (struct.unpack("I", sockfd.recv(4))[0] != 0):
        print "error"
        sys.exit(0);

def verifyFunction(sockfd, idx):
    packet = struct.pack("B", TYPE_VERIFY)
    packet += struct.pack("H", 2)
    packet += struct.pack("H", idx)
    sockfd.send(packet)
    sockfd.recv(2)
    if (struct.unpack("I", sockfd.recv(4))[0] != 0):
        print "error"
        sys.exit(0);

def runFunction(sockfd, idx, args):
    packet = struct.pack("B", TYPE_RUNFUNC)
    packet += struct.pack("H", 4 + 4 * len(args))

    packet += struct.pack("H", idx)
    packet += struct.pack("H", len(args))
    for arg in args:
        packet += struct.pack("I", arg)

    sockfd.send(packet)
    outlen = struct.unpack("H", sockfd.recv(2))[0]
    if (outlen != 0):
        return sockfd.recv(outlen)
    else:
        return ""

sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockfd.connect(('localhost', 1423))

operations = createOperation(OP_ADD, 4, 0, 0)
operations += createOperation(OP_ADD, 2, 3, 0)
operations += createOperation(OP_BGT, 0, 1, 2)
operations += createOperation(OP_OUT, 4, 0, 0)
function = createFunction(4, 2, operations)

addFunction(sockfd, function)

verifyFunction(sockfd, 0)

for i in range(1, 11):
    print int(runFunction(sockfd, 0, [i, i, 0, 1]), 16)
