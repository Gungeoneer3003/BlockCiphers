from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import sys

def submit():
    line = input("Enter a line: ")
    cleaned = line.replace(';', '%3B').replace('=', '%3D')
    joined = ''.join(["userid=456; userdata=", cleaned, ";session-id=31337"])

    #Encrypt Message

    return joined

def verify(line):
    decrypted = line
    #Decrypt line
    return (";admin=true;" in decrypted) #Should never come back true