# Fibinary

### Solution
Based on the source code, `c2f()` transforms each character into an ASCII value and is encrypted using the first 11 number from the Fibonacci Sequence. For each character that is passed into c2f, 8 ‘bits’ of `0's` and `1's` is written to flag.enc.
```python
fib = [1, 1]
for i in range(2, 11):
	fib.append(fib[i - 1] + fib[i - 2])

def c2f(c):
	n = ord(c)
	b = ''
	for i in range(10, -1, -1):
		if n >= fib[i]:
			n -= fib[i]
			b += '1'
		else:
			b += '0'
	return b

flag = open('flag.txt', 'r').read()
enc = ''
for c in flag:
	enc += c2f(c) + ' '
with open('flag.enc', 'w') as f:
	f.write(enc.strip())
```
The flag can be decrypted by brute forcing all printable ASCII characters using the exact same `c2f()` function.
```python
#!/usr/bin/python3
import string

charlist = list(string.printable)

fib = [1, 1]
for i in range(2, 11):
    fib.append(fib[i - 1] + fib[i - 2])

def c2f(c):
    n = ord(c)
    b = ''
    for i in range(10, -1, -1):
        if n >= fib[i]:
            n -= fib[i]
            b += '1'
        else:
            b += '0'
    return b


enc_charlist = [c2f(i) for i in charlist]
charlist = dict(zip(charlist, enc_charlist))

with open("flag.enc") as enc:
    flag = enc.read()
    for k, v in charlist.items():
        flag = flag.replace(v, k)
    print(flag)
```
**Flag:** `corctf{b4s3d_4nd_f1bp!113d}`
