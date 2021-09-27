#------------------------------------------------------------------------------------------------
# Names: Adam Yerden & Trevor Butler
# Course: CIS 475 Intro to Cryptography
# Assignement: RSA chat program       
# Due: Friday, May 18 2021
#------------------------------------------------------------------------------------------------
import socket
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Encrypts messages using public key and AES key
#
# Parameters: randomKey, n, e
# Return: encryptedMessage
def encrypt(randomKey, n, e):
    encryptedMessage = pow(randomKey, e, n)
    return encryptedMessage

# Create socket for the server
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 8080
serverSocket.bind(('0.0.0.0', port))
print("Server listening on port", port)
serverSocket.listen(5)

# Create key for AES and send to client 
randomKey = random.getrandbits(128)
conn, addr = serverSocket.accept()
data = conn.recv(4096)
decodedData = data.decode()
publicKeys = decodedData.split(' ')
n = publicKeys[0]
e = publicKeys[1]

# Display Public Keys
print("\n---------- Public keys ----------\n")
print('n = ' + str(n) + '\n')
print('e = ' + str(e))

# Encrypt AES key and send it to client
encryptedRandomKey = encrypt(int(randomKey), int(n), int(e))
print("\n---------- AES Key ----------\n")
print(str(encryptedRandomKey).encode())
print('\n------------------------------------------------------------------\n')
print("To disconnect send message 'disconnect'\n")
print('------------------------------------------------------------------\n')

conn.send(str(encryptedRandomKey).encode())

# Convert key to bytes
key = randomKey.to_bytes(16, 'big')
connection = True

# Create cipher, Decrypt plaintext, print cipher and plain text
while connection == True:
    cipher = AES.new(key, AES.MODE_CBC)
    plaintext = input("Type Message for Client:\n").encode()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    conn.send((str(ciphertext) + '||' +  str(cipher.iv)).encode())

    cipherText_and_iv = (conn.recv(4096)).decode()
    decodedData = cipherText_and_iv.split('||')
    cipherTextFromClient = eval(decodedData[0])
    print('\n------------------------------------------------------------------\n')
    print('Cipher:\n' + str(cipherTextFromClient) + '\n')
    iv = eval(decodedData[1])

    cipherFromClient = AES.new(key, AES.MODE_CBC, iv=iv)
    plainTextFromClient = unpad(cipherFromClient.decrypt(cipherTextFromClient), AES.block_size)
    chat = plainTextFromClient.decode()

    print('Message Received from Client:\n' + chat + '\n')
    print('------------------------------------------------------------------\n')

    # disconnect on keyword "disconnect"
    if chat == 'disconnect':
        conn.close()
        print('You have been disconnected')
        connection = False
