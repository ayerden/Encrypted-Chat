# Names: Adam Yerden and Trevor Butler
# Course: CIS 475 Intro to Cryptography
# Assignment: RSA chat Program
# Due: May 14, 2021

Included Files: server.py, client.py

# Problem:

Follow the given scenario:

Import AES into server and client. Client will implement RSA encryption method to generate
public keys (n, e). Client will share these public keys with server. Server picks a 128 bit key.
These key is encrypted and sent to Client, Client then decrypts this key using private key d. Both Server and Client have the key to implement AES. Finally, messages sent between the two are encrypted/decrypted using AES key.

# How to run the program:

1. Open two terminals.

2. From whichever terminal you prefer run the server by typing the following command:

> python server.py 

3. No on the other terminal run the following command:

> python client.py

4. You will see client and server interchanging keys, once that is over, from the Server terminal enter a message to the client.

5. Message back to back from terminal to terminal as you like.

6. Terminate the program by typing the keyword 'done' from the Client terminal.
