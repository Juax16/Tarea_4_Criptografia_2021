import libnum #instalar libnum
from Cryptodome.Util.number import * #instakar Cryptodome
import hashlib #instalar hashlib
import sys

def gen_key(k):
    p = getPrime(k)
    q = getPrime(k)
    n = p**2 * q
    while True:
        g = getRandomRange(1, n-1)
        g_p = pow(g, p-1, p**2)
        if pow(g_p, p, p**2) == 1:
            break
    r = getRandomRange(1, n-1)
    h = pow(r, n, n)
    return (n, g, h,p,q)

 
def encrypt(m, n, g, h):
    Mlen = len(bin(bytes_to_long(m))[2:])

    k = len(bin(n)[2:])//3

    if (k<Mlen): 
      print("Prime too small for message")
      sys.exit()
    rlen = getRandomRange(1, k - Mlen)
   

    R = long_to_bytes(getRandomInteger(rlen))
    r = bytes_to_long(hashlib.sha256(m + R).digest())
    c = (pow(g, bytes_to_long(m + R), n) * pow(h, r, n)) % n
    return c

def L(x, p):
    return (x-1)//p
 
def do_divide(x, y, p):
    return x*(libnum.invmod(y, p))

def decrypt(c,p,g):
    cp = pow(c, p-1, p**2)
    gp = pow(g, p-1, p**2)

    x = do_divide(L(cp, p), L(gp, p), p) % p
    return (long_to_bytes(x))



