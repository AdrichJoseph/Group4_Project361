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


def server():
    serverPort = 12000

    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(('', serverPort))
        serverSocket.listen(5)  # Listen for 5 connections

        #    try:
        #        connectionSocket, addr = serverSocket.accept()
        #        connectionSocket.send('Enter your username: '.encode('ascii'))

        # menu :
        #        connectionSocket.send('\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tChoice: '.encode(
        #            'ascii'))

        # do we use a dictionary to store the emails? :
        #       emailContents = {}

        while True:

            # receive the message from the client
            message = connectionSocket.recv(2048).decode('ascii')

            # if message == 1 then create/send email functionality is executed
            if message == '1':
                pass



            # if message == 2 then inbox display is executed
            elif message == '2':
                pass


            # if message == 3 then display contents functionality is executed
            elif message == 3:
                pass



            # Still need to apply encryption later
            elif message == '4':
                # Terminate the connection
                terminationMessage = "The connection is terminated with the server"
                # Send the termination message and close socket then break the loop
                connectionSocket.send(terminationMessage.encode('ascii'))
                connectionSocket.close()
                break

            # if the answer is not 1,2 or 3 then ask again.
            connectionSocket.send(
                '\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tChoice: '.encode(
                    'ascii'))




    except socket.error as e:
        serverSocket.close()

        sys.exit(1)



    except:
        serverSocket.close()

        sys.exit(0)


# -------

server()