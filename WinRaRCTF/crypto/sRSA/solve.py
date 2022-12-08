#!/usr/bin/env python3
from Crypto.Util.number import *

n = 5496273377454199065242669248583423666922734652724977923256519661692097814683426757178129328854814879115976202924927868808744465886633837487140240744798219
e = 431136
ct = 3258949841055516264978851602001574678758659990591377418619956168981354029697501692633419406607677808798749678532871833190946495336912907920485168329153735

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1
 
    if (m == 1):
        return 0
 
    while (a > 1):
 
        # q is quotient
        q = a // m
 
        t = m
 
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
 
        # Update x and y
        y = x - q * y
        x = t
 
    # Make x positive
    if (x < 0):
        x = x + m0
 
    return x
 
# Input
a = e
m = n
 
rev_mod = modInverse(a, m)

pt = (rev_mod * ct) % n
pt_in_bytes = long_to_bytes(pt)

print(pt)
print(pt_in_bytes)