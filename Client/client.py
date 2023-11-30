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
from Crypto.Util.Padding import pad, unpad



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


# Encrypts messages
def encrypt(message, cipher):
    ct_bytes = cipher.encrypt(pad(message.encode('ascii'), 32))
    return ct_bytes


#Decrypts messages, use this when receiving from server
def decrypt(socket_recv, cipher):
    Padded_message = cipher.decrypt(socket_recv)
    unpadded = unpad(Padded_message,32).decode('ascii')
    return unpadded


def sendEmailProtocol(username, clientSocket, cipher):

    destination = input("Enter destinations (separated by ;): ")
    title = input("Enter title: ")
    contentType = input("Would you like to load contents from a file? (Y/N) ")

    #message content from a file
    if (contentType.upper() == 'Y'):
        fileName = input("Enter filename: ")
        file = open(fileName, 'r')
        content = file.read()
        file.close()

    else:
        content = input("Enter message contents: ")

    #create email
    length = len(content)
    email = f"From: {username}\nTo: {destination}\nTitle: {title}\nContent Length: {length}\nContent:\n{content}"
    # clientSocket.send(email.encode('ascii'))
    clientSocket.send(encrypt(email, cipher))

    print("The message is sent to the server.")

    return None


#Connects to the server and handles the math test
def client():
    # serverInput = input("Enter the server host name or IP: ")
    # serverName = serverInput
    serverName = "localhost"  # will fix this later just makes it easier for testing
    # Server Information
    serverPort = 13000

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
        clientSocket.send(encrypt("OK", cipher))

        menu = decrypt(clientSocket.recv(1024), cipher)
        clientResponse = input(menu)
        clientSocket.send(encrypt(clientResponse, cipher))
        while True:
            if clientResponse == "1":
                #print(clientResponse, "worked")
                sendEmailProtocol(username, clientSocket)

                # ----
            if clientResponse == "2":  # if client response is 2

                encrypted_inbox_list = clientSocket.recv(1024)  # receive encrypted inbox list
                inbox_list = decrypt(encrypted_inbox_list, cipher)  # decrypt inbox list
                print(inbox_list)  # print inbox list
                # -----
                
            if clientResponse == "3":
                #Recv and print the messgae asking for email to display option
                encrypted_inbox_choice_msg = clientSocket.recv(1024)
                inbox_choice_msg = decrypt(encrypted_inbox_choice_msg, cipher)
                print(inbox_choice_msg)

                #Get inbox choice and send it to server
                inboxNum = input()
                clientSocket.send(encrypt(inboxNum, cipher))


            elif clientResponse == "4":
                print("The connection is terminated with the server.")
                break

            # restart the choice loop
            # menu = decrypt(clientSocket.recv(1024), cipher)
            clientResponse = input(menu)
            clientSocket.send(encrypt(clientResponse, cipher))

        # Client terminate connection with the server
        clientSocket.close()

    except socket.error as e:
        print('An error occured:', e)
        clientSocket.close()
        sys.exit(1)

def sendEmailProtocol(username, clientSocket):
    destination = input("Enter destinations (separated by ;): ")
    title = input("Enter title: ")
    contentType = input("Would you like to load contents from a file? (Y/N) ")

    #message content from a file
    if (contentType.upper() == 'Y'):
        fileName = input("Enter filename: ")
        file = open(fileName, 'r')
        content = file.read()
        file.close()
    
    else:
        content = input("Enter message contents: ")

    #create email
    length = len(content)
    email = f"From: {username}\nTo: {destination}\nTitle: {title}\nContent Length: {length}\nContent:\n{content}"
    clientSocket.send(email.encode('ascii'))
    print("The message is sent to the server.")

    return None

def displayEmailContents():

# ----------
client()
