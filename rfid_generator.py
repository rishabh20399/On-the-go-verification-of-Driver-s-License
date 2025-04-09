# Function to encrypt a message using RSA
def encrypt(message, private_key):
    e, n = private_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

# Function to decrypt an encrypted message using RSA
def decrypt(encrypted_message, public_key):
    d, n = public_key
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
    # print("Decrypted: ",decrypted_message)
    return decrypted_message

# Private key (e, n) for RSA encryption
private_key = (269, 323)
public_key=(197, 323)

#This is where digital signature is created
#here we can encrypt the 
#encrypted rfid (according to real life scenario)
message = [84, 192, 84, 205] #this is encrypted version of "2024"

# Encrypt the message using the provided private key
# encrypted_message = encrypt(message, private_key)
decrypted_message= decrypt(message,public_key)

# Print the encrypted message (list of encrypted values)
# print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)

