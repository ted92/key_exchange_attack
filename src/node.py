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
from utils import OK, Verifier, aes_encode, TIME, generate_nonce, verify_nonce

SHARED_KEY = b'TheForceIsStrong'  # 16bit AES key


class Node:
    """
    Node class.
    process flow:
    ( 1 ) N --> S: {N_N}K
    ( 2 ) S --> N: N_N, {N_S}K
    ( 3 ) N --> S: N_S
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
        ( 1 ) step one of the algorithm
        """
        self.nonce = generate_nonce()
        n, ciphertext, tag = aes_encode(self.aes, self.nonce)
        to_send = {'n': n, 'c': ciphertext, 't': tag}  # dictionary to send to the server
        self.nodesocket.sendall(pickle.dumps(to_send))
        data = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        return data

    def final_proof(self, data):
        """
        send the final proof back, server nonce in plaintext
        :param data:    dict, data received from the server
                        {   'n_n'   : N_N,
                            'n'     : nonce_encryption,
                            'c'     : ciphertext,
                            't'     : tag }
        ( 3 ) step three of the algorithm
        """
        n = data['n']
        c = data['c']
        t = data['t']
        n_s = aes_decode(n, c, t, self.aes)
        self.nodesocket.sendall(pickle.dumps(n_s))
        data = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        return data


# todo: server side
def main(argv):
    try:
        _, _ = getopt.getopt(argv, "p:", ["path="])
    except getopt.GetoptError:
        print("node.py -p <file_path>")
        sys.exit(2)
    c = Node()
    data = c.setup()  # data should contain the step ( 2 ) of the algorithm
    # { 'n_n': N_N, 'n': nonce_encryption, 'c': ciphertext, 't': tag }
    n_n = data['n_n']
    if verify_nonce(n_n, c.nonce):
        # if server verified the nonce, then continues with step ( 3 )
        data = c.final_proof(data)
        print(data)
    else:
        print(Colors.FAIL + "ERROR! Server Key is not verified!" + Colors.ENDC)
        # todo: Server might not PASS if it changes its key
    c.nodesocket.sendall(pickle.dumps('hello'))
    data = c.nodesocket.recv(MAX_SIZE)
    msg = pickle.loads(data)
    print(msg)


if __name__ == "__main__":
    main(sys.argv[1:])
