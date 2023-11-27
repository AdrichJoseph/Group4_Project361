# Ayub, Christine, Evan, Kipp

# Goal:

import socket
import os
import glob
import datetime
import json
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def decrypt_user_pass_message(encrypted_msg):
    dec_key = RSA.importKey(open('server_private.pem', "rb").read())
    cipher2 = PKCS1_OAEP.new(dec_key)
    user, passwd = (cipher2.decrypt(encrypted_msg).decode("ascii")).split("\n")
    return user, passwd


def generate_sym_key():
    sym_key = get_random_bytes(int(256/8))
    return sym_key


def encrypt_with_client_public_key(username, sym_key):
    rsa_key = RSA.importKey(open(f'{username}_public.pem', "rb").read())
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(sym_key)

# Encrypts messages
def encrypt(message_string, cipher):
    ct_bytes = cipher.encrypt(pad(message_string.encode('ascii'), 16))
    return ct_bytes


#Decrypts messages
def decrypt(socket_recv, cipher):
    Padded_message = cipher.decrypt(socket_recv)
    unpadded = unpad(Padded_message, 32).decode('ascii')
    return unpadded

# Opens connnection to clients and handles the math test
def server():
    # Server port
    serverPort = 13000

    # Create server socket that uses IPv4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:', e)
        sys.exit(1)

    # Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:', e)
        sys.exit(1)

    print('The server is ready to accept connections')

    # The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    while 1:
        try:
            # Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            pid = os.fork()
            with open("user_pass.json", 'r') as file:
                user_pass_dict = json.load(file)


            # If it is a client process
            if pid == 0:

                serverSocket.close()

                sym_key = generate_sym_key()
                # this variable will need to be used when decrypting
                cipher = AES.new(sym_key, AES.MODE_ECB)
                # decrypt username and password
                username, passwd = decrypt_user_pass_message(connectionSocket.recv(1024))
                # Check to see if user/pass combo is in json file
                if username in user_pass_dict and user_pass_dict[username] == passwd:
                    # sending the sym_key encrypted with the client_public.pem
                    connectionSocket.send(encrypt_with_client_public_key(username, sym_key))
                    ok_message = decrypt(connectionSocket.recv(1024), cipher)
                    print(f"Connection Accepted and Symmetric Key Generated for client: {username}")

                else:
                    # this runs if the user/pass combo is not in json
                    connectionSocket.send("Invalid username or password".encode("ascii"))
                    print(f"The received client information: {username} is invalid (Connection Terminated)")
                    connectionSocket.close()
                    serverSocket.close()
                    return

                menu = 'Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tChoice: '
                #
                connectionSocket.send(encrypt(menu, cipher))
                message = decrypt(connectionSocket.recv(1024), cipher)
                while True:
                    if message == "1":
                        print(message, "worked")
                    if message == "2":
                        print(message, "worked")
                    if message == "3":
                        print(message, "worked")
                    if message == "4":
                        print(f"Terminating connection with {username}")
                        break
                    connectionSocket.send(encrypt(menu, cipher))
                    message = decrypt(connectionSocket.recv(1024), cipher)

                # restart the choice loop
                connectionSocket.close()

                return

            # Parent doesn't need this connection
            connectionSocket.close()

        except:
            print('Goodbye')
            serverSocket.close()
            sys.exit(0)


# -------
server()