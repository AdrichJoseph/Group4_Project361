import socket
import os
import glob
import datetime
import json
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA1


# calculate the sha1 hash of the message
def calculate_sha1(message):
    sha1 = SHA1.new() 
    sha1.update(message.encode('ascii')) 
    return sha1.hexdigest() # return the hash value


def send_message_with_integrity(socket, message, cipher):
    # Encrypt the message
    encrypted_message = encrypt(message, cipher)

    # Calculate SHA-1 hash of the original message
    hash_value = calculate_sha1(message)

    # Send the encrypted message and the hash
    socket.send(encrypted_message)
    socket.send(hash_value.encode('ascii'))


def receive_message_with_integrity(socket, cipher):
    # Receive the encrypted message and the hash
    encrypted_message = socket.recv(1024)
    received_hash = socket.recv(40).decode('ascii')  # SHA-1 produces a 40-character hash

    # Decrypt the message
    decrypted_message = decrypt(encrypted_message, cipher)

    # Verify integrity by recalculating the hash
    calculated_hash = calculate_sha1(decrypted_message)

    if received_hash != calculated_hash:
        print("Integrity check failed. Message may have been tampered with.")
        return None

    return decrypted_message


# Encrypts the user and pass string (msg) with the server public key and prepares it to be sent using
# the client socket
def encrypt_user_pass(user_pass_string):
    rsa_key = RSA.importKey(open('server_public.pem', "rb").read())
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(user_pass_string.encode('ascii'))


# Decrypts the message that lets us know if user and pass is correct, and RETURNS the generated sym_key from
# server, if user/pass is incorrect it will print invalid and disconnect
def decrypt_with_client_key(username, encryped_sym_key, clientSocket):
    try:
        rsa_key = RSA.importKey(open(f'{username}_private.pem', "rb").read())
        cipher = PKCS1_OAEP.new(rsa_key)
        sym_key = cipher.decrypt(encryped_sym_key)
        return sym_key

    except Exception as e:
        print(encryped_sym_key.decode("ascii"))
        print("Terminating")
        clientSocket.close()
        sys.exit(0)


def encrypt(message_string, cipher):
    ct_bytes = cipher.encrypt(pad(message_string.encode('ascii'), 16))
    return ct_bytes

def decrypt(socket_recv, cipher):
    Padded_message = cipher.decrypt(socket_recv)    # error here
    if not Padded_message:
        return ""
    unpadded = unpad(Padded_message, 16).decode('ascii')
    return unpadded



def sendEmailProtocol(username, clientSocket, cipher):
    send_the_email_string = receive_message_with_integrity(clientSocket, cipher)

    destination = input("Enter destinations (separated by ;): ")

    while 1:
        title = input("Enter title: ")

        # title length checker
        if len(title) <= 100:
            break
        else:
            print("Error: exceeded maximum character limit of 100, please try again:")

    contentType = input("Would you like to load contents from a file? (Y/N) ")

    while 1:
        # message content from a file
        if (contentType.upper() == 'Y'):
            fileName = input("Enter filename: ")
            file = open(fileName, 'r')
            content = file.read()

            file.close()

        else:
            content = input("Enter message contents: ")

        length = len(content)

        # Content length check
        if length <= 1000000:
            break
        else:
            print("Error: exceeded maximum character limit of 1,000,000, please try again:")

    #create email
    emailInfo = f"From: {username}\nTo: {destination}\nTitle: {title}\nContent Length: {length}\nContents:\n"
    send_message_with_integrity(clientSocket, emailInfo, cipher)

    print("Email content received. It is not saved on the client side.")

    # send content separately
    for i in range(0, length, 2047):
        send_message_with_integrity(clientSocket, str(content[i:i + 2047]), cipher)

    print("The message is sent to the server.")

    return None



#Connects to the server and email system
def client():
    serverInput = input("Enter the server host name or IP: ")
    serverName = serverInput
    # Server Information
    serverPort = 12000

    # Create client socket that useing IPv4 and TCP protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:', e)
        sys.exit(1)

    try:
        # Client connect with the server
        clientSocket.connect((serverName, serverPort))
        username = input("Enter the username: ")
        password = input("Enter your password: ")
        msg = username + "\n" + password
        clientSocket.send(encrypt_user_pass(msg))

        # check to see if user and pass is accepted by server
        sym_key = decrypt_with_client_key(username, clientSocket.recv(1024), clientSocket)
        cipher = AES.new(sym_key, AES.MODE_ECB)
        send_message_with_integrity(clientSocket, "OK", cipher)

        menu = receive_message_with_integrity(clientSocket, cipher)
        clientResponse = input(menu)
        send_message_with_integrity(clientSocket, clientResponse, cipher)

        while True:
            if clientResponse == "1":
                sendEmailProtocol(username, clientSocket, cipher)


            if clientResponse == "2":  # if client response is 2
                encrypted_inbox_list = clientSocket.recv(1024)  # receive encrypted inbox list
                inbox_list = decrypt(encrypted_inbox_list, cipher)  # error here
                print(inbox_list)  # print inbox list


            if clientResponse == "3":
                whichIndexString = decrypt(clientSocket.recv(1024), cipher)
                index = input(whichIndexString)
                send_message_with_integrity(clientSocket, index, cipher)

                size = receive_message_with_integrity(clientSocket, cipher)

                print(size)
                content = ""

                while (len(content) < int(size)):
                    content += receive_message_with_integrity(clientSocket, cipher)
                print(content, "\n")

            elif clientResponse == "4":
                print("The connection is terminated with the server.")
                break

            # restart the choice loop
            clientResponse = input(menu)
            send_message_with_integrity(clientSocket, clientResponse, cipher)

        # Client terminate connection with the server
        clientSocket.close()

    except socket.error as e:
        print('An error occured:', e)
        clientSocket.close()
        sys.exit(1)

# ----------
client()
