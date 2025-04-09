import socket
import rsa
import pickle
import time
import random


# Setup ids
device_id = "device"
database_id = "database"

# Setup RSA keys for digital signature
public_keys = {"device":(73, 323), "database":(179, 323)}  # Dictionary to store public keys of pkda, client
private_keys= {"device":(217, 323)}
host = 'localhost'  # Server's hostname or IP address
device_port = 9000  
database_port = 9001

#Setup Diffie-Hellman keys for communication
prime_modulus = 23  # Prime modulus (p)
generator = 5       # Generator (g)
device_DH_private_key = random.randint(1, prime_modulus - 1) # Device's DH private key



# Modular exponentiation
def power(a, b, c):
    x = 1
    y = a
 
    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c
        y = (y * y) % c
        b = int(b / 2)
 
    return x % c

# Function to generate a Diffie-Hellman public key (based on private key, prime modulus, and generator)
def generate_public_key(private_key, prime_modulus, generator):
    public_key = power(generator, private_key, prime_modulus)
    return public_key

# Function to compute the shared session key based on received public key, private key, and prime modulus
def compute_shared_key(received_public_key, private_key, prime_modulus):
    shared_key = power(received_public_key, private_key, prime_modulus)
    return shared_key

# Function to encrypt a message using a shared session key
def encrypt_message(message, shared_key):
    en_msg = []
    for i in range(0, len(message)):
        en_msg.append(message[i])

    for i in range(0, len(en_msg)):
        en_msg[i] = shared_key * ord(en_msg[i])
    return en_msg

# Function to decrypt a message using a shared session key
def decrypt_message(encrypted_message, shared_key):
    dr_msg = []
    for i in range(0, len(encrypted_message)):
        dr_msg.append(chr(int(encrypted_message[i]/shared_key)))
    dmsg = ''.join(dr_msg)
    return dmsg



# Sending . . .
def send_message(sock, private_key, message):
    encrypted_message = rsa.encrypt(message, private_key)
    sock.sendall(str(encrypted_message).encode())

# Receiving . . .
def receive_message(sock, public_key):
    while True:
        data = sock.recv(1024)
        if data:
            encrypted_message = eval(data.decode())
            decrypted_message = rsa.decrypt(encrypted_message, public_key)
            return decrypted_message

# Connecting . . .        
def connect_to_port(host,own_port,port_to_connect,id):
    sokt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sokt.bind((host, own_port))  # Bind to the specified port
    # s.listen(5)
    while True:  # Wait for client to come online to connect
        try:
            sokt.connect((host, port_to_connect))
            print("Connected to", id)
            return sokt
        except ConnectionRefusedError:
            # print("Connection to", id, "failed. Retrying...")
            time.sleep(3)  # Wait for 3 sec before retrying

def main(): 
    # STEP 0: Connecting the police device to the transport authority(TA) database
    s_database=connect_to_port(host,device_port,database_port,database_id)

    #STEP1: Carried out by the database . . .
    #STEP2: Receive public key of TA database 
    message2=eval(receive_message(s_database,public_keys[database_id]))
    print("Receiving [Generator, Prime_modulus, Public key] from TA database--> ",message2)
    database_DH_public_key=message2[2]

    #STEP3: Generate public key for police device and the session key
    device_DH_public_key = generate_public_key(device_DH_private_key,prime_modulus,generator)
    shared_key= compute_shared_key(database_DH_public_key,device_DH_private_key,prime_modulus)
    print("Shared key:", shared_key)

    #STEP4: Encrypt the RFID and send it to the TA database along with device_DH_public_key
    #NOTE: RFID is [84, 192, 84, 205]
    liscence = input("Enter the driver liscence's RFID\n(RFID is [84, 192, 84, 205] here): ")
    message3= [device_DH_public_key ,encrypt_message(liscence,shared_key)]
    print("Sharing [device_DH_public_key, encrypted_liscence_RFID] with TA database -->", message3)
    send_message(s_database,private_keys[device_id],str(message3))

    #STEP5/6: Carried out by the database . . .
    #STEP7: Receive the validation status of the liscence
    message5=str(receive_message(s_database,public_keys[database_id]))
    # message5_decrypt=decrypt_message(message5, shared_key)
    print("Liscence is: ", message5)
    
    #Step-7: Bonus part reciveing DATE AND TIME
    message6=str(receive_message(s_database,public_keys[database_id]))
    print("Date and Time is: ", message6)




if __name__ == "__main__":
    
    # database_public_key, database_private_key = rsa.generate_rsa_keys()
    device_public_key, device_private_key = public_keys[device_id], private_keys[device_id]
    print("device_public_key(RSA): ",device_public_key,"\ndevice_private_key(RSA): ", device_private_key)
    public_keys[device_id]=eval(str(device_public_key))

    main()