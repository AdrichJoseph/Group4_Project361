"""
Server Program for Secure Email Transfer.

This program performs the subprotocols for secure email transfer which includes sending the emails as specified by the client, 
and retrieving the inbox and emails of the client. Encryption and decryption is used for the security of the emails.

Author: Group 4 (Ayub Aden, Kipp Joseph, Evan White, Christine Kim)
"""

# Goal:

import socket
import os
from datetime import datetime
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

def encrypt(message_string, cipher):
    ct_bytes = cipher.encrypt(pad(message_string.encode('ascii'), 16))
    return ct_bytes

def decrypt(socket_recv, cipher):
    Padded_message = cipher.decrypt(socket_recv)
    if not Padded_message:
        return ""
    unpadded = unpad(Padded_message, 16).decode('ascii')
    return unpadded

"""
This is a helper method for the sendEmailProtocol method in which an email is saved into a text file
within the directory of the destination client.

Parameters:
emailTime: string
            email message which also includes the time and date the message as received
destination: string
            name of the destination client
username: string
            username of the client accessing the program
title: string
        title of the email
"""
def saveEmail(emailTime, destination, username, title):
    fileName = f"{username}_{title}.txt"
    pathfileName = os.path.join(f"./{destination}/", fileName)
    # check if directory exist
    if not os.path.isdir(destination):
        os.mkdir(f"./{destination}")
    emailFile = open(pathfileName, 'w')
    emailFile.write(emailTime)
    emailFile.close()

"""
This performs the sending email subprotocol in which the server receives the email from the client
and saves it into the directory/directories of the destination client(s).

Parameters:
connectionSocket: socket
            socket used to connect with client
username: string
            username of the client accessing the program
cipher:
            cipher used for encryption and decryption

Returns:
    None

"""
def sendEmailProtocol(connectionSocket, username, cipher):
    connectionSocket.send(encrypt("Send the email", cipher))
    #receive email info
    emailInfo = decrypt(connectionSocket.recv(2048), cipher)

    #parse email info
    lines = emailInfo.split('\n')

    for i in range(4):
        tokens = lines[i].split(':')

        if (i == 1):
            destination = tokens[1].replace(' ', '')

        elif (i == 3):
            length = tokens[1]

    print(f"An email from {username} is sent to {destination} has a content length of{length}")
    title = lines[2].split(" ")[1]

    if (length > 1000000) or (title > 100):
        print("Rejected: Maximum Character limit exceeded")
        return None

    #receive content
    content = ""
    while (len(content) < int(length)):
        content += decrypt(connectionSocket.recv(2048), cipher)
        
    #add time and date to email
    emailTime = f"{lines[0]}\n{lines[1]}\nTime and Date: {str(datetime.now())}\n{lines[2]}\n{lines[3]}\n{lines[4]}\n{content}"
    
    #save emails on destination clients directories
    #for multiple destinations
    if (';' in destination):
        clients = destination.split(';')

        for client in clients:
            saveEmail(emailTime, client, username, title)

    #for one destination
    else:
        saveEmail(emailTime, destination, username, title)

    return None

# Looks through client directories to find emails
def displayInbox(username):
    # Initialize a string variable to store the formatted inbox information.
    # This line sets up the headers for the inbox display. 
    inbox_list_str = "Index\t\tFrom\t\tDateTime\t\t\t\t\t\tTitle\n"  # Header for inbox list
    directory = f"./{username}/" # specify the directory to look in for the emails based on the username

    # Specify the directory path where the user's emails are stored.
    unsortedDirectory = os.listdir(directory)

    
    # Sort the list of files based on the modification time (latest first).
    sortedDirectory = sorted(unsortedDirectory, key=lambda x: os.path.getmtime(os.path.join(directory, x)))

    index = 0 # Initialize an index variable to keep track of email numbers.
    
    # loop through the files in the directory
    for filename in sortedDirectory:

        # Check if the file has a ".txt" extension, indicating it is an email file.
        if filename.endswith(".txt"):
            index += 1 #increment

            # Build the full path to the email file.
            file_path = os.path.join(directory, filename)

            # open the email file and read the first 4 lines to get the email information
            # such as the sender, recipient, date, and title.
            with open(file_path, 'r') as email:
                # remove the newline character at the end of the line
                email_from = email.readline().split(" ")[1].replace("\n", "")
                to = email.readline()
                date = email.readline().split(": ")[1].replace("\n", "")
                title = email.readline().split(" ")[1].replace("\n", "")
                # add the email information to the inbox_list_str variable
                inbox_list_str += f"{index}\t\t\t{email_from}\t\t{date}\t\t{title}\n"
    return inbox_list_str # return the formatted inbox information

# Opens connnection to clients and handles email system
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
            #pid = 0
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
                connectionSocket.send(encrypt(menu, cipher))
                message = decrypt(connectionSocket.recv(1024), cipher)
                while True:
                    if message == "1":
                        sendEmailProtocol(connectionSocket, username, cipher)

                        # -----------
                    if message == "2":
                        inbox_list_str = displayInbox(username)
                        connectionSocket.send(encrypt(inbox_list_str, cipher))

                    if message == "3":
                        connectionSocket.send(encrypt("Enter the email index you wish to view: ", cipher))
                        # Grabs the index
                        index = int(decrypt(connectionSocket.recv(1024), cipher))
                        # grabs the chosen email by the user
                        chosenEmail = displayInbox(username).split("\n")[index].split("\t")
                        emailFrom = chosenEmail[3]
                        title = chosenEmail[7]
                        fileName = f"./{username}/{emailFrom}_{title}.txt"
                        # opens the text file and grabs email contents
                        file = open(fileName, 'r')
                        content = file.read()
                        file.close()
                        size = len(content)
                        connectionSocket.send(encrypt(str(size), cipher))

                        for i in range(0, size, 2047):
                            encrypted = encrypt(str(content[i:i + 2047]), cipher)
                            connectionSocket.send(encrypted)

                    elif message == "4":
                        print(f"Terminating connection with {username}")
                        break

                    # connectionSocket.send(encrypt(menu, cipher))
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
