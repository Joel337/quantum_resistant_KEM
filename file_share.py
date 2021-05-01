from pprint import pprint
from Crypto.Cipher import AES
from Crypto import Random
import oqs, socket, sys, random, struct, os


#handle command line arguments
n = len(sys.argv)
HOST=False
HOST_IP='127.0.0.1'
PORT=1337
SERVER=False
ALG_Name="Kyber1024"
OUT=False
OUT_Dir = "default"
FILE="default"

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
    if sys.argv[i] == "-f" or sys.argv[i] =='-F':
        FILE=sys.argv[i+1]
    i+=1


#crypto settings
kems = oqs.get_enabled_KEM_mechanisms()
kemalg = ALG_Name
with oqs.KeyEncapsulation(kemalg) as settings:
    c_len = (settings.details['length_ciphertext'])
    p_len = (settings.details['length_public_key'])
shared_secret = b''

#For AES - credit to the internet for most of this
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key):
  
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)

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
            ciphertext, shared_secret_server = server.encap_secret(data)
            shared_secret = shared_secret_server
            conn.sendall(ciphertext)
            print("awaiting file")
            name = OUT_Dir +".enc"
            filetodown = open(name, "wb")
            while True:
                f_enc = b''
                print("Receiving")
                data = conn.recv(1024)
                if data == b'DONE':
                    print("Done Receiving")
                    break
                else:
                    f_enc += data
                filetodown.write(f_enc)
            filetodown.close()
            s.close()
            print("Connection has been closed.")
        print("Decrypting file.")
        decrypt_file(name, shared_secret)
        print("Your file was received and decrypted. It is named", OUT_Dir)
        os.remove(name)
        

#client
else:
    if FILE=="default":
        print("You have not specified a file. Please try again!")
        sys.exit()
    if not os.path.exists(FILE):
        print("It appears you have not specified a valid file name, please try again.")
        sys.exit()
    ciphertext = b''
    amount_received = 0
    expected = c_len 
    connection_addr = "client_to_"
    with oqs.KeyEncapsulation(kemalg) as client:
        print("You are transferring a file with AES256 and using the " + ALG_Name + " algorithm for a KEM.")
        
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
            while amount_received < expected:
                data = s.recv(c_len)
                amount_received += len(data)
                ciphertext+=data
            connection_addr += str(host)+":"+str(port)
            print("Received responsive ciphertext. Generating shared secret.")
            shared_secret_client = client.decap_secret(ciphertext)
            shared_secret = shared_secret_client
            print("Encrypting")
            encrypt_file(FILE, shared_secret)
            
            filetosend = open(FILE+".enc", "rb")
            data = filetosend.read(1024)
            while data:
                print("Sending. . . ")
                s.send(data)
                data = filetosend.read(1024)
            filetosend.close()
            s.send(b'DONE')
            print("Sending complete")
            s.close()
            os.remove(FILE+".enc")

