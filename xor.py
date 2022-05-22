def xor(a, b):
    for i in range(len(a)):
        print(i, ord(a[i]), ord(b[i % len(b)]), ord(a[i]) ^ ord(b[i % len(b)]), type(ord(a[i]) ^ ord(b[i % len(b)])), chr(ord(a[i]) ^ ord(b[i % len(b)])), chr(20))
    return "".join([chr(ord(a[i]) ^ ord(b[i % len(b)])) for i in range(len(a))])

print(xor("USERS", "ADMIN"))

print("="*20)
print(ord("U") ^ ord("A"), chr(ord("U") ^ ord("A")))
print("="*20)


def xor(a, b):
    return "".join([chr(ord(a[i]) ^ ord(b[i % len(b)])) for i in range(len(a))])
print(xor("USERS", "ADMIN"))
# '\x14\x17\x08\x1b\x1d'

from Crypto.Util.strxor import strxor
print(strxor(b"USERS", b"ADMIN"))

