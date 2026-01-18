from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sys

key = get_random_bytes(16) # 16 byte randomly generated pass
with open('keyFile2.txt', 'wb') as keyFile:
    keyFile.write(key)

def submit():
    plaintext = input("Enter a line: ")
    cleaned = plaintext.replace(';', '%3B').replace('=', '%3D')
    joined = ''.join(["userid=456; userdata=", cleaned, ";session-id=31337"])

    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv #Key is 16 bytes, so this should be 16

    ciphertext = cipher.encrypt(pad(joined, AES.block_size))
    # Referenced video recommends against including iv with ciphertext in production
    line = iv + ciphertext

    return line

def verify(line):
    #16 should maybe be a variable name
    iv = line[:16]
    ciphertext = line[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt line
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    #Redundant split for readability
    if (";admin=true;" in plaintext):
        return True #Normally, it should never reach here
    else:
        return False