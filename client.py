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



def client():
    try:

        Name = input("Enter the server host or IP: ")
        serverName = '127.0.0.1' if Name.lower() == 'localhost' else Name
        serverPort = 12000

        # create the socket and connect to the server
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((serverName, serverPort))




        # while loop for the client side

        while True:

            # ask for the client response
            clientResponse = input()
            clientSocket.send(clientResponse.encode('ascii'))

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
