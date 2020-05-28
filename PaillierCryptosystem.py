# Medya HAN
# PAILLIER CRYPTOSYSTEM

import random
import math

def gcd(a, b): # Greatest Common Divisor
  while b > 0:
    a, b = b, a % b
  return a

def lcm(a, b): # Least Common Multiple
  return a * b // gcd(a, b)

def L(u, n):
  return ((u - 1) // n)

def isPrime(u, T): # Function controlling whether or not prime
    v = 0
    w = u - 1
    while(w % 2 == 0):
        v += 1
        w = w // 2
    for _ in range(1, T + 1):
        nextt = False
        a = random.randint(2, u - 1)
        b = pow(a, w, u)
        if(b == 1 or b == u - 1):
            nextt = True
            continue
        for _ in range(1, v):
            b = (b ** 2) % u
            if(b == u - 1):
                nextt = True
                break
            if(b == 1):
                return False
        if(not nextt):
            return False
    return True

def createPrime(bit): # Function creating prime number for the given bit
    low = (1 << bit) + 1
    high = (1 << (bit + 1)) - 1

    while(True):
        prime = random.randint(low, high)
        if(prime % 2 == 1 and isPrime(prime, 15)):
            return prime

def reciprocal(a, n): # Function that takes the reciprocal of a number
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = n, a

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return (old_s % n)

def createG(n): # Function that creates the key g randomly
    g = random.randint(1, n - 1)
    while(gcd(g, n) != 1):
        g = random.randint(1, n - 1)
    return g

def textToDecimal(text): # Function that converts a text message to decimal
    list = []
    new = []
    for i in text:
        list.append(format(ord(i)))

    for j in list:
        if (len(j) == 2):
            new.append("0")
            new.append(j)
        else:
            new.append(j)
    return ''.join(new)

def decimalToText(decimal): # Function that converts a decimal message to text
    list = []
    new = []
    i = 0
    while(i != len(decimal)):
        list.append(''.join(decimal[i: (i + 3)]))
        i = i + 3
    for j in list:
        new.append(chr(int(j)))
    return ''.join(new)

def keygen(bit): # Function that creates the publickey (n, g) and privatekey (Lambda, Mu) keys.
    p = createPrime(int(bit / 2))
    q = createPrime(int(bit / 2))
    while(gcd(p * q, (p - 1) * (q - 1)) != 1):
        p = createPrime(int(bit / 2))
        q = createPrime(int(bit / 2))
    n = p * q

    Lambda = lcm(p-1, q-1)

    g = createG(n*n) # A random g is created
    while(gcd(L(pow(g, Lambda, n*n), n), n) != 1):
        g = createG(n*n)

    k = L(pow(g, Lambda, n*n), n)
    Mu = reciprocal(k, n) % n

    publickey = open("publickey.txt", "w")
    publickey.write(str(n) + "\n")
    publickey.write(str(g))
    publickey.close()

    privatekey = open("privatekey.txt", "w")
    privatekey.write(str(Lambda) + "\n")
    privatekey.write(str(Mu))
    privatekey.close()

    print("Keygen:\n")
    print("p: ", p)
    print("q: ", q)
    print("n: ", n)
    print("g: ", g)
    print("Lambda: ", Lambda)
    print("Mu: ", Mu)
    print("\n** Keys created successfully..")


def encrypt(plaintexttxt, publickeytxt):
    try:
        publickey = open(publickeytxt, "r")
    except FileNotFoundError:
        print("Keygen(n) function should be called first because there are no keys to encrypt..")

    n = int(publickey.readline())
    g = int(publickey.readline())
    publickey.close()

    plaintext = open(plaintexttxt, "r") # The message entered at the beginning is converted to decimal
    mesaj = plaintext.readline()
    m = int(textToDecimal(mesaj))
    plaintext.close()

    if(m < 0 or m >= n):
        raise Exception("Message cannot be smaller than '0' and larger than 'n'..")

    r = createPrime(int(math.log2(n))) # A random r is created
    while(r > n - 1):
        r = createPrime(int(math.log2(n)))

    c = (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)
    ciphertext = open("ciphertext", "w")
    ciphertext.write(str(c))
    ciphertext.close()

    print("\n================================\nEncrypt:\n")
    print("r: ", r)
    print("ciphertext: ", c)
    print("\n** Encryption is done..")

def decrypt(ciphertexttxt, privatekeytxt):
    try:
        privatekey = open(privatekeytxt, "r")
    except FileNotFoundError:
        print("Keygen(n) function should be called first because there are no keys to decrypt..")

    try:
        ciphertext = open(ciphertexttxt, "r")
    except FileNotFoundError:
        print("Keygen(n) function should be called first because there are no keys to decrypt..")

    try:
        publickey = open("publickey.txt", "r")
    except FileNotFoundError:
        print("Keygen(n) function should be called first because there are no keys to decrypt..")

    Lambda = int(privatekey.readline())
    Mu = int(privatekey.readline())
    privatekey.close()

    n = int(publickey.readline())
    publickey.close()

    c = int(ciphertext.readline())
    ciphertext.close()

    if(gcd(c, n*n) != 1):
        print("Faulty ciphertext..")

    if(c < 1 or c >= n*n or gcd(c, n*n) != 1):
        raise Exception("Ciphertext should be included in Z * n ^ 2..")

    m = (L(pow(c, Lambda, n*n), n) * Mu) % n
    message = decimalToText(str(m)) # m message in decimal state is converted to text

    plaintext2 = open("plaintext2", "w") # The decrypted message is written to the plaintext2 file
    plaintext2.write(str(message))
    plaintext2.close()

    print("\n================================\nDecrypt:\n")
    print("message: ", message)
    print("\n** Decryption is done..")

    plaintext = open("plaintext", "r")
    plaintext2 = open("plaintext2", "r")

    content = plaintext.readline()
    content2 = plaintext2.readline()

    plaintext.close()
    plaintext2.close()

    if (content == content2):
        print("\n================================\nControl:\n\nEncryption and decryption processes are correct..")



# RUNNING PAILLIER CRYPTOSYSTEM #

print("PAILLIER CRYPTOSYSTEM\n================================\n")

message = input("Enter message to be encrypted: ")

plaintext = open("plaintext", "w")
plaintext.write(str(message))
plaintext.close()

print("""\n================================\n\nOptions:\n\n- keygen(n)\n- encrypt("plaintext", "publickey.txt")\n- decrypt("ciphertext", "privatekey.txt")\n\n================================\n""")

n = int(input("Enter the number of bits: "))
print("\n================================")
keygen(n)
encrypt("plaintext", "publickey.txt")
decrypt("ciphertext", "privatekey.txt")
