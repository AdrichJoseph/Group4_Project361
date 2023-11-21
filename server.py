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

        while True:
            connectionSocket, addr = serverSocket.accept()

#            while True:




    except socket.error as e:
        serverSocket.close()

        sys.exit(1)



    except:
        serverSocket.close()

        sys.exit(0)



# -------

server()
