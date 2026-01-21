from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

#Commandline arguments (should check error-handling?)

def padding(data):
    l = AES.block_size - (len(data) % AES.block_size)
    padded_data = bytes([l]) * l
    return data + padded_data

def encEBC(byte_data, cipher):
    padded_byte_data = padding(byte_data)
    ciphertext = b""
    for i in range(0, len(padded_byte_data), AES.block_size):
        block = padded_byte_data[i:i+AES.block_size]
        ciphertext += cipher.encrypt(block)
    return ciphertext

def encCBC(plaintext, cipher, iv):
    padded_plaintext = padding(plaintext)
    ciphertext = b""
    previous_block = iv
    for i in range(0, len(padded_plaintext), AES.block_size):
        block = padded_plaintext[i:i+AES.block_size]
        block_to_encrypt = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block = cipher.encrypt(block_to_encrypt)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    return ciphertext


image_name = sys.argv[1]

# CONST_IMAGE_NAME = 'cp-logo.bmp' #not actually const, be careful!

key = get_random_bytes(16) # 16 byte randomly generated pass
iv = get_random_bytes(16)
with open('keyFile1.txt', 'wb') as keyFile:
    keyFile.write(key)
with open('ivFile1.txt', 'wb') as ivFile:
    ivFile.write(iv)

cipherECB = AES.new(key, AES.MODE_ECB)
cipherCBC = AES.new(key, AES.MODE_ECB)
bitmap_header = bytes(54)

try:
    file = open(image_name, "rb")
except FileNotFoundError:
    sys.exit("\nFile not opened. Potentially an invalid name?")
    
bitmap_header = file.read(54)
#file.seek(54, 0) not sure if this is necessary but included it incase we come back and it is later
imagedata = file.read()
file.close()

imagedataCopy = imagedata
encryptedECB = encEBC(imagedata, cipherECB)
encryptedCBC = encCBC(imagedataCopy, cipherCBC, iv)

otpECB = open("encryptedECB.bmp", "wb")
otpECB.write(bitmap_header)
otpECB.write(encryptedECB)
otpECB.close()

otpCBC = open("encryptedCBC.bmp", "wb")
otpCBC.write(bitmap_header)
# Referenced video recommends against including iv with ciphertext in production
# HK I do not think that this is correct. iv gives the initialization vector. We actually definately do NOT want to write this into the image.
# HK That gives any attackers an easy way to decrypt our program as we will have essentially given them the key.
# write(cipherCBC.iv) #Necessary for CBC decryption
otpCBC.write(encryptedCBC)
otpCBC.close()