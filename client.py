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

# test
def client():
    try:

        Name = input("Enter the server host or IP: ")
        serverName = '127.0.0.1' if Name.lower() == 'localhost' else Name
        serverPort = 12000

        # create the socket and connect to the server
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((serverName, serverPort))


#        while True:




    except socket.error as e:

        print('An error occured:', e)

        clientSocket.close()

        sys.exit(1)

    # ----------


client()
