# Ayub, Christine, Evan, Kipp

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
from Crypto.Hash import SHA1



def calculate_sha1(message):
    sha1 = SHA1.new()
    sha1.update(message.encode('ascii'))

    return sha1.hexdigest()


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

# Saves the email to the clients inbox/directory
def saveEmail(emailTime, destination, username, title):
    fileName = f"{username}_{title}.txt"
    pathfileName = os.path.join(f"./{destination}/", fileName)
    # check if directory exist
    if not os.path.isdir(destination):
        os.mkdir(f"./{destination}")
    emailFile = open(pathfileName, 'w')
    emailFile.write(emailTime)
    emailFile.close()


def sendEmailProtocol(username, clientSocket, cipher):
    # Send the message indicating to send an email
    send_message_with_integrity(clientSocket, "Send the email", cipher)

    # Receive the email info
    email_info = receive_message_with_integrity(clientSocket, cipher)

    # Parse email info
    lines = email_info.split('\n')

    destination, length = None, None

    for line in lines[:4]:
        key, value = line.split(':')
        key = key.strip()
        value = value.strip()

        if key == "To":
            destination = value
        elif key == "Content Length":
            length = int(value)

    if destination is None or length is None:
        print("Invalid email information received. Aborting.")
        return

    print(f"An email from {username} is sent to {destination} with a content length of {length}")
    title = lines[2].split(" ")[1]

    #content and title length checker
    if (int(length) > 1000000) or (len(title) > 100):
        print("Rejected: Maximum Character limit exceeded")
        return None

    # Receive the content
    content = ""
    while len(content) < length:
        content += receive_message_with_integrity(clientSocket, cipher)

    # Add time and date to email
    email_time = f"{lines[0]}\n{lines[1]}\nTime and Date: {str(datetime.now())}\n{lines[2]}\n{lines[3]}\n{lines[4]}\n{content}"

    # Save emails in destination clients' directories
    # For multiple destinations
    if ';' in destination:
        clients = destination.split(';')

        for client in clients:
            saveEmail(email_time, client, username, title)

    # For one destination
    else:
        saveEmail(email_time, destination, username, title)

    print("Email successfully saved.")
    return None



# Looks through client directories to find emails
def displayInbox(username):
    inbox_list_str = "Index\t\tFrom\t\tDateTime\t\t\t\t\t\tTitle\n"  # Header for inbox list
    directory = f"./{username}/"
    unsortedDirectory = os.listdir(directory)

    sortedDirectory = sorted(unsortedDirectory, key=lambda x: os.path.getmtime(os.path.join(directory, x)))

    index = 0
    for filename in sortedDirectory:
        if filename.endswith(".txt"):
            index += 1
            file_path = os.path.join(directory, filename)
            with open(file_path, 'r') as email:
                email_from = email.readline().split(" ")[1].replace("\n", "")
                to = email.readline()
                date = email.readline().split(": ")[1].replace("\n", "")
                title = email.readline().split(" ")[1].replace("\n", "")
                inbox_list_str += f"{index}\t\t\t{email_from}\t\t{date}\t\t{title}\n"
    return inbox_list_str

# Opens connnection to clients and handles email system
def server():
    # Server port
    serverPort = 12000
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
            #pid = os.fork()
            pid = 0
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

                    ok_message = receive_message_with_integrity(connectionSocket, cipher)
                    print(f"Connection Accepted and Symmetric Key Generated for client: {username}")

                else:
                    # this runs if the user/pass combo is not in json
                    connectionSocket.send("Invalid username or password".encode("ascii"))
                    print(f"The received client information: {username} is invalid (Connection Terminated)")
                    connectionSocket.close()
                    serverSocket.close()
                    return

                #send menu options
                menu = 'Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tChoice: '
                send_message_with_integrity(connectionSocket, menu, cipher)

                #recv client choice
                message = receive_message_with_integrity(connectionSocket, cipher)

                while True:
                    if message == "1":
                        sendEmailProtocol(username, connectionSocket, cipher)

                        # -----------
                    if message == "2":
                        inbox_list_str = displayInbox(username)
                        send_message_with_integrity(connectionSocket, inbox_list_str, cipher)

                    if message == "3":
                        send_message_with_integrity(connectionSocket, "Enter the email index you wish to view: ", cipher)

                        # Grabs the index
                        index = int(receive_message_with_integrity(connectionSocket, cipher))

                        # grabs the chosen email by the user, parse
                        chosenEmail = displayInbox(username).split("\n")[index].split("\t")
                        emailFrom = chosenEmail[3]
                        title = chosenEmail[7]
                        fileName = f"./{username}/{emailFrom}_{title}.txt"

                        # opens the text file and grabs email contents
                        file = open(fileName, 'r')
                        content = file.read()
                        file.close()
                        size = len(content)
                        send_message_with_integrity(connectionSocket, str(size), cipher)

                        for i in range(0, size, 2047):
                            send_message_with_integrity(connectionSocket, str(content[i:i + 2047]), cipher)

                    elif message == "4":
                        print(f"Terminating connection with {username}")
                        break

                    message = receive_message_with_integrity(connectionSocket, cipher)

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
