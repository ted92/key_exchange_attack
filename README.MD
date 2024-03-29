# Key Possesion Proof - Reflection Attack
Implementation in Python of a reflection attack, performed during a key possession-proof
protocol between two parties.

## Getting Started - Protocol
The protocol between a Node `N` and a Server `S` ensures that both parties are in
possession of a certain key `K`. If `N_N` is a freshly generated nonce
from `N`, and `N_S` is generated by `S`, then the protocol communication flow is the
following:

```
N --> S: {N_N}K
S --> N: N_N, {N_S}K
N --> S: N_S
```
The protocol is designed to prove to `S` and `N` that they share a key `K` with each other.
However, a malicious node `E` could make `S` believe that he posses the
right key `K` even though it does not. How is that possible?

### Reflection Attack

In this scenario the attacker, `E`, opens two different sessions
with the target, `S`. In the second session, `E` sends as its nonce, the encrypted `N_S`
that `S` sent previously, then `S` will decrypt it and send it back to `E`.
Now `E` has the plaintext of the nonce to send back to the first session opened.

The attack works as follows:
```
E --> S: N_E **not relevant for the attack**    .1
S --> E: {N_S}K, {N_E}_DECRYPTED_WITH_K	        .1
E --> S: {N_S}K	                                .2
S --> E: {N_S2}, N_S                            .2
E --> S: N_S                                    .1
```
The numbers .1 and .2 identify the two different sessions that `E` opens with `S`.


### Prerequisites

Libraries used, you might require to install:
1. pycryptodome
2. websocket
3. websocket-client

These libraries are listed in the `requirements.txt` file. So the only command you need to run is:
```bash
pip install -r requirements.txt
```

However, if you want to install single package just use:
```bash
❯ pip install pycryptodome
```

To check you comply with the requirements you can check with:
```bash
❯ pip check
No broken requirements found.
```

### Scripts
The scripts and folders are the following:
```
.
├── [3.1K]  README.md
└── [ 16K]  src
    ├── [3.4K]  evil_node.py
    ├── [2.8K]  node.py
    ├── [4.8K]  server.py
    └── [2.1K]  utils.py
```
* The `node.py` script implements an honest node, sharing `K` with `S`;
* The `evil_node.py` implements an instance of `E`, and even if it does not
share the same `K` with `S`, it makes `S` believe it does;
* `utils.py` contains some useful functions shared by both parties;
* `server.py` implements the party that makes sure a new node has the shared `K`. Hence
gives an approval or a denial to the connecting node `N`.

## Running
To run the scripts open two different sessions, node and server.
In the server session:
```bash
❯ python server.py
Listening on: 127.0.0.1:8300
... waiting for a connection
```
In the node session:
```bash
❯ python node.py
The message is authentic!
CONGRATULATIONS, YOU ARE VERIFIED!
```
And the result back in the server session:
```bash
Got a connection from ('127.0.0.1', 64756)
New connection added:  ('127.0.0.1', 64756)
Connection from :  ('127.0.0.1', 64756)
The message is authentic!
Client at  ('127.0.0.1', 64756)  disconnected...
```

### Running without K

If the node does not share the same key `K`, then the outcome is in node session:

```bash
❯ python node.py
ERROR: Server Key is not verified!
Key incorrect or message corrupted!
ERROR: Ah-ah-ah! You didn't say the magic word!
```
While in the server session:
```bash
Got a connection from ('127.0.0.1', 65113)
New connection added:  ('127.0.0.1', 65113)
Connection from :  ('127.0.0.1', 65113)
Key incorrect or message corrupted!
Client at  ('127.0.0.1', 65113)  disconnected...
```

## Authors

* **Enrico Tedeschi** - *Initial work* - [reflection_attack](https://github.com/ted92/key_exchange_attack)
