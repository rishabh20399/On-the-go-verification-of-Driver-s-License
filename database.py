import socket
import rsa
import pickle
import time
import random
import rfid_generator

# Setup ids
device_id = "device"
database_id = "database"

# Setup for public keys
public_keys = {"device":(73, 323), "database":(179, 323), "liscence":(197, 323)}  # Dictionary to store public keys of database, device
private_keys= {"database":(251, 323)}
host = 'localhost'  # Server's hostname or IP address
device_port = 9000  
database_port = 9001

#Setup Diffie-Hellman keys for communication
prime_modulus = 23  # Prime modulus (p)
generator = 5       # Generator (g)
database_DH_private_key = random.randint(1, prime_modulus - 1) # Database's DH private key




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

def validate_liscence(rfid):
    if rsa.decrypt(rfid,public_keys["liscence"])==rfid_generator.decrypt(rfid,public_keys["liscence"]):
        return True
    else:
        return False

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
    # STEP 0: Connecting the police device to the transport authority database
    s_device=connect_to_port(host,database_port,device_port,device_id)

    #STEP1: Generating and sending the public key to the police device
    database_DH_public_key = generate_public_key(database_DH_private_key,prime_modulus,generator)
    message1=[generator,prime_modulus,database_DH_public_key]
    print("Sharing [Generator, Prime_modulus, Public key] with the police device -->", message1)
    send_message(s_device,private_keys[database_id],str(message1))

    #STEP2/3/4: Carried out by the police device . . .
    #STEP5: Receive the encrypted liscence RFID and Diffie-Hellman public key of police device
    message3=eval(receive_message(s_device,public_keys[device_id]))
    print("Receiving [device_DH_public_key ,encrypted_liscence_RFID] from police device--> ",message3)
    device_DH_public_key=message3[0]
    shared_key= compute_shared_key(device_DH_public_key,database_DH_private_key,prime_modulus)
    print("Shared key:", shared_key)
    license=decrypt_message(message3[1],shared_key)
    print("liscence: ",license)

    #STEP6: Validate the liscence and send valid or not
    message4="Invalid"
    if validate_liscence(eval(license)):
        message4="Valid"
    # print(message4)
    
    #adding timestamp to the message sent from the databse to device
    #Generate timestamp
    timestamp = time.time()
    #Convert timestamp to string
    timestamp_string = time.strftime('%Y-%m-%d %H:%M', time.localtime(timestamp))
    # print("Timestamp as string:", timestamp_string_encrypt)
    
    #encrypting the message to be sent using Deffie_Hellman and then sending it to device
    # message4_encrypt=encrypt_message(message4, shared_key)
    send_message(s_device,private_keys[database_id],message4)
    #Bonus-Part: Date and Time sent securely
    send_message(s_device,private_keys[database_id],timestamp_string)


if __name__ == "__main__":
    # database_public_key, database_private_key = rsa.generate_rsa_keys()
    database_public_key, database_private_key = public_keys[database_id], private_keys[database_id]
    print("database_public_key(RSA): ",database_public_key,"\ndatabase_private_key(RSA): ", database_private_key)
    public_keys[database_id]=eval(str(database_public_key))
    main()
