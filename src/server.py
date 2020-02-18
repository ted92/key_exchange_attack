#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

import socket, threading
import sys
import rsa
import pickle
from utils import Colors, PORT, MAX_SIZE, OK, NO_CONTENT, NOTFOUND, HOST, Verifier, aes_encode, aes_decode, TIME
import datetime
import time

AES_KEY = b'TheForceIsStrong'  # 16bit AES key


class ClientThread(threading.Thread):
    def __init__(self, client_address, clientsocket):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        self.client_address = client_address
        print("New connection added: ", self.client_address)

    def run(self):
        print("Connection from : ", self.client_address)
        msg = ''
        while True:
            data = self.csocket.recv(MAX_SIZE)
            message = pickle.loads(data)
            code = OK
            if code == OK:
                self.csocket.sendall(pickle.dumps(code))
                break
            print("from client", msg)
            self.csocket.send(bytes(msg, 'UTF-8'))
        print("Client at ", self.client_address, " disconnected...")


class Server:
    """
    Server class -- The server, upon request, needs the client to prove it has a certain key K, and the
    server needs to prove that back to the client.

    While the server is up and running, the students have to try to make the server believe they have the secret key.

    MESSAGE FORMAT:
    {   'id'        : <id>,
        'sequence'  : <sequence_n>,
        'type'      : <type of connection>,
        'content'   : <message content>
        }
    """
    def __init__(self):
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket object
        self.aes = AES_KEY  # aes key
        self.clientsocket = {}
        self.session_list = []  # list of dict with all the open sessions and their status
        # { 'id'        : id,
        #   'sequence'  : sequence}

    def run(self):
        """
        it runs the server
        :return:
        """
        # bind to the port
        self.serversocket.bind((HOST, PORT))
        print("Listening on: " + Colors.BOLD + HOST + ":" + str(PORT) + Colors.ENDC)
        print("... waiting for a connection", file=sys.stderr)
        id_clientsocket = 0
        try:
            while True:
                # queue up to 5 requests
                self.serversocket.listen(5)
                clientsocket, addr = self.serversocket.accept()
                print("Got a connection from " + Colors.WARNING + "%s" % str(addr) + Colors.ENDC)
                self.clientsocket[str(id_clientsocket)] = clientsocket
                newthread = ClientThread(addr, self.clientsocket[str(id_clientsocket)])
                id_clientsocket += 1
                newthread.start()
        finally:
            self.clientsocket.close()

    def parse_message(self):
        """
        get meaning of the message
        {   'session_id'    : id,
            'sequence'      : sequence,
            'msg'           : message
                        }
        """


if __name__ == "__main__":
    try:
        srv = Server()
        srv.run()
    except KeyboardInterrupt:
        srv.clientsocket.close()
        print(Colors.WARNING + "Shutting down ... " + Colors.ENDC)

#
# import socket, threading
# LOCALHOST = "127.0.0.1"
# PORT = 8080
# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# server.bind((LOCALHOST, PORT))
# print("Server started")
# print("Waiting for client request..")
# while True:
#     server.listen(1)
#     clientsock, clientAddress = server.accept()
#     newthread = ClientThread(clientAddress, clientsock)
#     newthread.start()

