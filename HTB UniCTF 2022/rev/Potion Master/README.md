# Potion Master

### Solution
```
# After stripping the flag format and checking the length, several checks are performed against constants
# 1. The difference between each chunk of two characters
# 2. XORing together each chunk of three characters
# 3. The sum of each chunk of four characters
# 4. Checking every 5th character against a constant
# This script implements the first 3 checks (the fourth was added later as a guard against ambiguous solutions)

from z3 import *
from functools import reduce
import operator

a = [-43, 61, 58, 5, -4, -11, 64, -40, -43, 61, 62, -51, 46, 15, -49, -44, 47, 4, 6, -7, 47, 7, -59, 52, -15, 11, 7, 61, 0]
b = [6, 106, 10, 0, 119, 52, 51, 101, 0, 0, 15, 48, 116, 22, 10, 58, 125, 100, 102, 33]
c = [304, 357, 303, 320, 304, 307, 349, 305, 257, 337, 340, 309, 428, 270, 66]

s = Solver()
flag = [BitVec(f"flag_{i}", 8) for i in range(58)]
for i in range(len(flag)):
    s.add(flag[i] > 0x20)
    s.add(flag[i] < 0x7f)

for i in range(0, 58, 2):
    s.add(flag[i] - flag[i+1] == a[i//2])

for i in range(0, 58, 3):
    s.add(reduce(operator.xor, flag[i:i+3], 0) == b[i//3])

for i in range(0, 58, 4):
    s.add(sum(flag[i:i+4]) == c[i//4])

assert s.check() == sat
m = s.model()
print(bytes([int(repr(m[f])) for f in flag]))
```
