import random
import math
import socket
import time


# List of sockets to select from
socket_ids = {}

def bind_clientSocket(host,port,id):
    id_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    id_socket.bind((host, port))
    id_socket.listen(5)  
    print(id," is listening on port", port)
    socket_ids[id]=id_socket
    return id_socket

# Function to check if a number is prime
def is_prime(num):
    print("is_prime")
    if num <= 1:
        return False
    elif num <= 3:
        return True
    elif num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

# Function to generate large prime numbers
def generate_prime():
    # print("generate_prime")
    while True:
        print("while True")
        prime_candidate = random.getrandbits(1024)
        # prime_candidate = 97
        print(is_prime(prime_candidate))
        
        if is_prime(prime_candidate):
            print("prime_candidate")
            return prime_candidate

# Function to calculate gcd
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Function to calculate modular inverse
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# Function to generate RSA keys with random value of e
def generate_rsa_keys():
    print("Enter Prime numbers p and q")
    p = int(input())
    q = int(input())

    # Generate large prime numbers p and q
    # p = generate_prime()
    # q = generate_prime()
    # print("FLAG 1")
    
    # Compute n and phi(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose encryption key e
    e = random.randint(2, phi_n - 1)  # Choose random value of e
    # print("FLAG 2")
    while gcd(e, phi_n) != 1:  # Ensure e and phi_n are coprime
        e = random.randint(2, phi_n - 1)
    # print("FLAG 3")
    
    # Compute decryption key d
    d = mod_inverse(e, phi_n)
    

    
    # Public key: (e, n), Private key: (d, n)
    public_key = (e, n)
    private_key = (d, n)
    
    
    return public_key, private_key

# Function to encrypt a message using RSA
def encrypt(message, private_key):
    e, n = private_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    # print("Encrypted:\n",''.join(str(p) for p in encrypted_message))
    return encrypted_message

# Function to decrypt an encrypted message using RSA
def decrypt(encrypted_message, public_key):
    d, n = public_key
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
    # print("Decrypted: ",decrypted_message)
    return decrypted_message


# Sample implementation
if __name__ == "__main__":
    
    # Setup PKDA
    pkda_public_keys = {}  # Dictionary to store public keys of clients
    print("FLAG -1")

    # Setup Clients
    client1_id = "client1"
    client2_id = "client2"
    # print("FLAG 0")
    
    client1_public_key, client1_private_key = generate_rsa_keys()
    client2_public_key, client2_private_key = generate_rsa_keys()
    # print("FLAG 4")

    print("client1_public_key = ",client1_public_key,"\nclient1_private_key = ",client1_private_key,"\nclient1_private_key = ",client2_public_key,"\nclient1_private_key = ",client2_private_key)

    # # Store public keys of clients in PKDA
    # store_public_key_in_pkda(client1_id, client1_public_key, pkda_public_keys)
    # store_public_key_in_pkda(client2_id, client2_public_key, pkda_public_keys)

    print(pkda_public_keys)

    # # Client 1 requests public key of itself from PKDA
    # client1_public_key_from_pkda = get_public_key_from_pkda(client1_id, pkda_public_keys)

    # Client 1 requests public key of Client 2 from PKDA

    # Client 1 and Client 2 exchange encrypted messages
    # message_to_client2 = "Hello, Client 2!"
    # encrypted_message_to_client2 = encrypt(message_to_client2, client2_public_key_from_pkda)
    # decrypted_message_to_client2 = decrypt(encrypted_message_to_client2, client2_private_key)

    # message_to_client1 = "Hi, Client 1!"
    # encrypted_message_to_client1 = encrypt(message_to_client1, client1_public_key_from_pkda)
    # decrypted_message_to_client1 = decrypt(encrypted_message_to_client1, client1_private_key)

    # # Print decrypted messages
    # print("Decrypted message for Client 2:", decrypted_message_to_client2)
    # print("Decrypted message for Client 1:", decrypted_message_to_client1)
