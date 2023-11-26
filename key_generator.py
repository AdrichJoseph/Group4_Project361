from Crypto.PublicKey import RSA  # import RSA key generator from pycryptodome library
import os


# Create directory for server and client
def createDirectory():
    server_dir = "./Server"  # path to server directory
    client_dir = "./Client"  # path to client directory

    for directory in [server_dir, client_dir]:  # loop through server and client directory path
        if not os.path.isdir(directory):  # check if directory exist
            os.mkdir(directory)  # create directory if it does not exist


def generateKey():
    server_key = RSA.generate(2048)  # generate RSA key with 2048 bits for the server key

    # open file to write the public key and private key for server and client in binary mode
    with open("./Client/server_public.pem", "wb") as public_server, \
            open("./Server/server_private.pem", "wb") as private_server:
        public_server.write(server_key.publickey().export_key())
        private_server.write(server_key.export_key())

    for i in range(5):  # Loop through the 5 clients that we have
        user_key = RSA.generate(2048)  # Then we generate an RSA key with 2048 bits for each client

        public = user_key.publickey().export_key()  # export public key

        # We open the files to write the public keys for the client in both client and server directories in binary mode
        # Use {i+1} to name the files as client1, client2, client3, client4, client5
        with open(f"./Client/client{i + 1}_public.pem", "wb") as public_file, \
                open(f"./Server/client{i + 1}_public.pem", "wb") as file_server:
            public_file.write(public)  # Write the client's public key to a file in the client directory
            file_server.write(public)  # Write the client's public key to a file in the server directory

        # assign private key to private variable and export it
        private = user_key.export_key()
        # open file to write the private key for client in the client directory in binary mode
        with open(f"./Client/client{i + 1}_private.pem", "wb") as private_file:
            private_file.write(private)  # write private key to file in binary mode


if __name__ == '__main__':
    createDirectory()
    generateKey()