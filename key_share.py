from pprint import pprint
import oqs, socket, sys, os, hashlib


#handle command line arguments
n = len(sys.argv)
HOST=False
HOST_IP='127.0.0.1'
PORT=1337
SERVER=False
ALG_Name="NTRU-HPS-2048-677"
OUT=False
OUT_Dir = ""
HELP=False


if n <2:
    print("Error, no arguments provided.")
    sys.exit()

i = 0
while i < n:
    if sys.argv[i] == "-h" or sys.argv[i] =='-H':
        HOST=True
        HOST_IP=sys.argv[i+1]
    if sys.argv[i] == "-p" or sys.argv[i] =='-P':
        PORT=int(sys.argv[i+1])
    if sys.argv[i] == "-s" or sys.argv[i] =='-S':
        SERVER=True
    if sys.argv[i] == "-a" or sys.argv[i] =='-A':
        ALG_Name=sys.argv[i+1]
    if sys.argv[i] == "-o" or sys.argv[i] =='-O':
        OUT = True
        OUT_Dir=sys.argv[i+1]
    if sys.argv[i] == "-help" or sys.argv[i] =='-HELP':
        HELP=True
    i+=1


#crypto settings
kems = oqs.get_enabled_KEM_mechanisms()
kemalg = ALG_Name
with oqs.KeyEncapsulation(kemalg) as settings:
    c_len = (settings.details['length_ciphertext'])
    p_len = (settings.details['length_public_key'])
shared_secret = b''

#Help output
if HELP==True:
    print(
'''
=======================================================
| KEY_SHARE v0.1 Help		Project 2, CS_GY 6903 | 
| Additional documentation available on github        |
| at github.com/Joel337/quantum_resistant_KEM.        |
| OQS Information available at openquantumsafe.org    |
|                                                     |
| To use this program, run two copies, one on each    |
| machine you wish to have the symmetric key.         |
|						      |
| Arguments:                                          |
| -h = specify host                                   |
| -p = specify port                                   |
| -s = set as server                                  |
| -a = set algorithm (see below)                      |
| -o = output filename for key                        |
|         					      |
| Algorithms:					      |
| Any algorithms supported by OQS should work!        |
| This has been tested on:			      |
| Kyber: Kyber512, Kyber768, Kyber1024 		      |
| NTRU: NTRU-HPS-2048-509, NTRU-HPS-2048-677,         |
|       NTRU-HPS-4096-821                             |
|                                                     | 
| Syntax example:                                     |
| Arguments must be directly followed by the value.   |
| key_share.py -s -p 1337 -a Kyber1024                |
| key_Share.py -h 10.0.2.15 -p 1337 -a Kyber1024      |
| -o mykey.bin 					      |
=======================================================

'''
    )


#server function
if SERVER == True:
    ciphertext = b''
    connection_addr ="server_key_from_"
    with oqs.KeyEncapsulation(kemalg) as server:
        if HOST==True:
            host=HOST_IP
        else:
            host=''
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, int(PORT)))
            s.listen(1)
            print("Listening on port " + str(PORT))
            conn, addr = s.accept()
            with conn:
                print("Connection from ", addr)
                connection_addr += str(addr[0])+":"+str(addr[1])
                data = conn.recv(p_len)
                print("Received public key starting with ", data[0:10].hex()) 
                ciphertext, shared_secret_server = server.encap_secret(data)
                shared_secret = shared_secret_server
                print("sending ciphertext.")
                conn.sendall(ciphertext)
                s.close()
                print("Connection has been closed.")
        if OUT: #specify the output file.  Does not currently make new directories. 
            connection_addr = OUT_Dir

        f = open(connection_addr, "wb")
        f.write(shared_secret)
        f.close()
        print("Print the sha3 hash of the secret is ", hashlib.sha3_256(shared_secret_server).hexdigest())
        print("The secret has been written to ", connection_addr)

#client
else:
    ciphertext = b''
    amount_received = 0
    expected = c_len 
    connection_addr = "client_key_to_"
    with oqs.KeyEncapsulation(kemalg) as client:
        print("The security features of your selected algorithm are: ")
        pprint(client.details)
        if HOST==True:
            host=HOST_IP
        else:
            host='127.0.0.1'
        port = int(PORT)
        
        public_key = client.generate_keypair()

        print("Trying to connect to " + str(host) + ":" + str(port))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(public_key)
            print("Connected and sent public key starting with ", public_key[0:10].hex())
            while amount_received < expected:
                data = s.recv(c_len)
                amount_received += len(data)
                ciphertext+=data
            connection_addr += str(host)+":"+str(port)
        print("Received responsive ciphertext. Generating shared secret.")

        shared_secret_client = client.decap_secret(ciphertext)
        shared_secret = shared_secret_client
        if OUT: #specify the output file if you want. Does not currently make new directories. 
            connection_addr = OUT_Dir
            isFile = os.path.isfile(OUT_Dir)

        f = open(connection_addr, "wb")
        f.write(shared_secret)
        f.close()
        print("Print the sha3 hash of the secret is ", hashlib.sha3_256(shared_secret_client).hexdigest())
        print("The shared secret has been written to ", connection_addr)
