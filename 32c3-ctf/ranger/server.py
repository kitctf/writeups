import subprocess
import time
import os
import sys
import socket
import atexit
import random
import shutil
import struct

CHALLSRC = '/home/challenge/challtree'
PASSWDREAD = '/home/challenge/pwread'
CHALL = './ranger'

def p32(x):
    return struct.pack('<I', x)

def recv_until(r, pattern):
    buf = ''
    while True:
        data = r.recv(1)
        if not data:
            return ''
        buf += data
        if pattern in buf:
            return buf

def send_cmd(r, cmd, data='', wait_for_ack=True):
    r.sendall(cmd + p32(len(data)) + data)
    if wait_for_ack:
        return recv_until(r, 'OK\n')
    return ''

def spawn_fakeuser(port):
    sys.stdout.close()
    sys.stderr.close()
    sys.stdin.close()
    time.sleep(10)
    flagpw = subprocess.check_output(PASSWDREAD).decode('hex')
    r = socket.socket()
    r.connect(('127.0.0.1', port))
    send_cmd(r, '\x01', 'flag')
    send_cmd(r, '\x05')
    send_cmd(r, '\x03', flagpw)
    send_cmd(r, '\x07')
    send_cmd(r, '\x00', wait_for_ack=False)
    r.close()

def spawn_challenge(port, ip):
    shutil.copytree(CHALLSRC, path_from_port(port))
    atexit.register(cleanup, port)
    os.chdir(path_from_port(port))
    sys.stdout.write('Spawning your instance on port %i on this server. Your IP is %s\n' % (port, ip))
    sys.stdout.flush()
    subprocess.call([CHALL, str(port), ip])
    sys.stdout.write('Exiting...\n')
    sys.stdout.flush()

def path_from_port(port):
    return '/tmp/%05i/' % port

def cleanup(port):
    shutil.rmtree(path_from_port(port))

def do_fork(ip):
    port = get_rand_port()
    try:
        pid = os.fork()
        if pid > 0:
            spawn_fakeuser(port)
        else:
            spawn_challenge(port, ip)
    except OSError, e:
        sys.stderr.write('Failed to fork: %s\n' % e.strerror)
        sys.exit(1)
    sys.exit(0)

def get_rand_port():
    while True:
        port = random.randrange(1025, 2**16)
        if not os.path.exists(path_from_port(port)):
            return port

if __name__ == '__main__':
    do_fork(os.environ['REMOTE_HOST'])
