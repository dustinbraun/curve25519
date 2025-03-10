print("hi")

p = pow(2, 255) - 19

x = (p + 0) % p
y = (p + 1) % p
z = (p - 1) % p

def to_LE(x):
    return bytearray(x.to_bytes(32, 'little'))

def print_LE_cpp_bytearray(x: int):
    s = to_LE(x)
    for b in s:
        print(format(b, '#04x') + ",")



print(to_LE(x))
print(to_LE(y))
print(to_LE(z))

a = 0x23846304_53225234_54564322_45345631_19485734_49384834_95323244_29485723
b = 0x63235693_32653455_23522352_23322564_43854855_66523324_23446342_32215462
c = (a * b) % p

d = pow(a, -1, p)

e = pow(a, 2) % p

f = (a*a)%p

print_LE_cpp_bytearray(p)


