#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

from utils import Colors, MAX_SIZE, PORT, aes_decode
import socket
import sys
import rsa
import getopt
import re
import pickle
import time
from utils import OK, Verifier, aes_encode, TIME, generate_nonce

SHARED_KEY = b'TheForceIsStrong'  # 16bit AES key


class Node:
    """
    Node class.
    process flow:
    N --> S: {N_N}K
    S --> N: N_N, {N_S}K
    N --> S: N_S
    """
    def __init__(self):
        self.nodesocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server = ("127.0.0.1", PORT)
        self.aes = SHARED_KEY
        self.nodesocket.connect(self.server)
        self.sequence = 0
        self.nonce = None
        self.id = generate_nonce()

    def close_connection(self):
        """
        close the open connection
        :return:
        """
        self.nodesocket.close()

    def setup(self):
        """
        nonce creation and setup with the server.
        """
        self.nonce = generate_nonce()


def main(argv):
    try:
        _, _ = getopt.getopt(argv, "p:", ["path="])
    except getopt.GetoptError:
        print("node.py -p <file_path>")
        sys.exit(2)
    c = Node()
    c.setup()
    c.nodesocket.sendall(pickle.dumps('hello'))
    data = c.nodesocket.recv(MAX_SIZE)
    msg = pickle.loads(data)
    print(msg)


if __name__ == "__main__":
    main(sys.argv[1:])
