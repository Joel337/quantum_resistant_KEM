from pprint import pprint
import oqs, socket, sys


#handle command line arguments
n = len(sys.argv)
HOST=False
HOST_IP='127.0.0.1'
PORT=1337
SERVER=False
ALG_Name="NTRU-HPS-2048-677"
OUT=False
OUT_Dir = ""


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
    i+=1


#crypto settings
kems = oqs.get_enabled_KEM_mechanisms()
kemalg = ALG_Name
with oqs.KeyEncapsulation(kemalg) as settings:
    c_len = (settings.details['length_ciphertext'])
    p_len = (settings.details['length_public_key'])
shared_secret = b''

#server function
if SERVER == True:
    ciphertext = b''
    connection_addr =""
    with oqs.KeyEncapsulation(kemalg) as server:
        if HOST==True:
            host=HOST_IP
        else:
            host='127.0.0.1'
        print("Listening on " + host + " port " + str(PORT))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, int(PORT)))
            s.listen()
            conn, addr = s.accept()
            print("Connection from ", addr)
            connection_addr += str(addr[0])+":"+str(addr[1])
            data = conn.recv(p_len)
            print("Received public key starting with ", data[0:10]) 
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
        print("The server's shared secret is ", shared_secret)
        print("The secret has been written to ", connection_addr)

#client
else:
    ciphertext = b''
    amount_received = 0
    expected = c_len 
    connection_addr = "client_to_"
    with oqs.KeyEncapsulation(kemalg) as client:
        print("The security features of your selected algorithm are: ")
        pprint(client.details)
        if HOST==True:
            host=HOST_IP
        else:
            host='127.0.0.1'
        port = int(PORT)
        
        public_key = client.generate_keypair()

        print("Trying to connect to " + str(port))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(public_key)
            print("Connected and sent public key starting with ", public_key[0:10])
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
        print("The client shared secret is ", shared_secret_client)
