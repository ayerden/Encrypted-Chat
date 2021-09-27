#------------------------------------------------------------------------------------------------
# Names: Adam Yerden & Trevor Butler
# Course: CIS 475 Intro to Cryptography
# Assignement: RSA chat program       
# Due: Friday, May 18 2021
#------------------------------------------------------------------------------------------------
import math
import socket
from Crypto.Cipher import AES
from random import randrange, getrandbits
from Crypto.Util.Padding import pad, unpad

# Greates common divisor algorithm
#
# Parameters: a, b
# Return: a
def gcd(a, b):
    if(b == 0):
        return a
    else:
        return gcd(b, a%b)

# Test if n is prime
#
# Parameters: n, k=128
# Return: boolean
def isPrime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True

# Generates possible prime numbers
#
# Parameters: length
# Return: n
def generatePossiblePrime(length):
    n = getrandbits(length)
    n |= (1 << length - 1) | 1
    return n

# Generates prime numbers of length 1024
#
# Parameters: length = 1024
# Return: n
def generatePrimeNumbers(length = 1024):
    n = 4
    while not isPrime(n, 128):
        n = generatePossiblePrime(length)
    return n

# Pulverizer algorithm
#
# Parameters: A, B, phi
# Return: y2
def pulverizer(A, B, phi):
    Q , R = divmod(A, B)
    x1 = 1
    y1 = 0
    x2 = 0
    y2 = 1
    while (R != 0):
        A = B
        B = R
        tempx2 = x2
        tempy2 = y2
        x2 = x1 - (Q * x2)
        y2 = y1 - (Q * y2)
        x1 = tempx2
        y1 = tempy2
        Q , R = divmod(A, B)
    if (y2 < 0):
        return phi - abs(y2)
    return y2

# Decrypts AES key using private key d
# k**d % n
#
#returns decryptedKey
def decrypt(encryptedKey):
    decryptedKey = pow(encryptedKey, d, n)
    return decryptedKey

# Generate p, q, n, & phi
p = generatePrimeNumbers()
q = generatePrimeNumbers()
n = p * q
phi = (p - 1) * (q -1)

# Generate e
GCDcheck = 0
e = 284184701247
while GCDcheck == 0:
    if gcd(phi, e) != 1:
        e = e + 1
    else:
        GCDcheck = 1

# Generate d
d = pulverizer(phi, e, phi) % phi

# Create socket for client Connect to port 1234
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect(('0.0.0.0', 8080))

# Send encodeded public keys
print("\n---------- Public Keys ----------\n")
print('n = ' + str(n) + "\n\ne = " + str(e) + '\n')
clientSocket.send((str(n) + " " + str(e)).encode())

# Decode the AES key, Decrypt key by using integer value
data = clientSocket.recv(4096)
encryptedKey = data.decode()
decryptedKey = decrypt(int(encryptedKey))

# Save value of AES key as bytes and print
key = decryptedKey.to_bytes(16, 'big')
print("---------- AES key ----------")
print('\n' + str(key) + '\n')
print("------------------------------------------------------------------\n")
print("To disconnect send message 'disconnect'\n")
connection = True

# Create cipher, Decrypt plaintext, print cipher and plain text
while connection == True:
    cipherTextIV = (clientSocket.recv(4096)).decode()
    decodedData = cipherTextIV.split('||')

    cipherText = eval(decodedData[0])
    print("------------------------------------------------------------------\n")
    print("Cipher:\n" + str(cipherText) + '\n')
    iv = eval(decodedData[1])
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(cipherText), AES.block_size)
    chat = plaintext.decode()
    
    print('Message Received from Server:\n' + chat + '\n')
    print("------------------------------------------------------------------\n")
    sendCipher = AES.new(key, AES.MODE_CBC)
    plainTextToServer = input("Type Message for Server:\n").encode()
    print()
    
    cipherTextToServer = sendCipher.encrypt(pad(plainTextToServer, AES.block_size))
    clientSocket.send((str(cipherTextToServer) + '||' +  str(sendCipher.iv)).encode())

    # disconnect on keyword "disconnect"
    if plainTextToServer.decode() == 'disconnect':
        clientSocket.close()
        print('\n' + 'You have been disconnected')
        connection = False
