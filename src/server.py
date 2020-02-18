#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

import socket
import sys
import rsa
import pickle
from utils import Colors, PORT, MAX_SIZE, OK, NO_CONTENT, NOTFOUND, HOST, Verifier, aes_encode, aes_decode, TIME
import datetime
import time

AES_KEY = b'TheForceIsStrong'  # 16bit AES key


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
        self.clientsocket = None
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
        # queue up to 5 requests
        self.serversocket.listen(5)
        self.clientsocket, addr = self.serversocket.accept()
        print("Got a connection from " + Colors.WARNING + "%s" % str(addr) + Colors.ENDC)
        try:
            while True:
                # establish a connection
                data = self.clientsocket.recv(MAX_SIZE)
                if not data:
                    time.sleep(2)
                    pass
                else:
                    message = pickle.loads(data)
                    code = OK
                    if code == OK:
                        self.clientsocket.sendall(pickle.dumps(code))
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

