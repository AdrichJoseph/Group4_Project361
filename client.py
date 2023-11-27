# Group 4
# Ayub, Christine, Evan, Kipp

# Goal:


import socket
import os
import glob
import datetime
import json
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
#gang


# test
def client():

    #key = ... key generator

    cipher = AES.new(key, AES.MODE_ECB)

    try:

        name = input("Enter the IP or name: ")
        serverName = '127.0.0.1' if name.lower() == 'localhost' else name
        serverPort = 12000

        # create the socket and connect to the server
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((serverName, serverPort))


        # while loop for the client side

        while True:

            # recv from username and passward prompt from server
            inMessage = unpad(cipher.decrypt(clientSocket.recv(2048)), 16).decode('ascii')
            print(inMessage)

            #get user info
            username = input()
            password = input("Enter your password: ")

            #create string to send
            msg = username + "\n" + password

            #send user info !(Need to add server public key encryption)
            clientSocket.send(msg.encode('ascii'))

            #Recv and print menu
            inMessage = unpad(cipher.decrypt(clientSocket.recv(2048)), 16).decode('ascii')
            print(inMessage)

            # if client is = 1 ,create and send email
            if clientResponse == '1':
                pass




            # when user choose 2 print list of emails

            elif clientResponse == '2':
                pass

            #if 3 ,  Display email contents
            elif clientResponse == '3':
                pass

            # if 4, terminate  # still need to apply encryption
            elif clientResponse == '4':
                server_response = clientSocket.recv(2048).decode('ascii')
                print(server_response)
                clientSocket.close()
                break

            # client response is anything else,  send the message as 4 since the server will receive it and will automatically
            # trigger the else statement in their side.

            menu = clientSocket.recv(2048).decode('ascii')
            print(menu, end='')




    except socket.error as e:

        print('An error occured:', e)

        clientSocket.close()

        sys.exit(1)

    # ----------


client()
