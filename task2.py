from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sys

key = get_random_bytes(16) # 16 byte randomly generated pass
with open('keyFile2.txt', 'wb') as keyFile:
    keyFile.write(key)

#Hard coded user data to allow easier manipulation, capitalized for 'sudo-const' consistency
USERDATA = "You’re the man now, dog"

def submit():
    #plaintext = input("Enter a line: ")
    plaintext = USERDATA
    cleaned = plaintext.replace(';', '%3B').replace('=', '%3D')
    joined = ''.join(["userid=456; userdata=", cleaned, ";session-id=31337"])

    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv #Key is 16 bytes, so this should be 16 bytes

    ciphertext = cipher.encrypt(pad(joined.encode(), AES.block_size))
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
    print(plaintext)

    #Redundant split for readability
    if (";admin=true;" in plaintext):
        return True #Normally, it should never reach here
    else:
        return False

'''
This method will work by messing with the ciphertext to
1. Mess with the beginning to add ";admin=true;"
This works because we know the beginning is more than 16 bytes
'''

def xor_two_str(a,b):
    xored = []
    for i in range(max(len(a), len(b))):
        xored_value = ord(a[i%len(a)]) ^ ord(b[i%len(b)])
        xored.append(hex(xored_value)[2:])
    return ''.join(xored)

def addAdmin(line):
    iv = line[16:]
    ciphertext = line[:16]
    codeInjection = ";admin=true;"
    messageStart = "userid=456; userdata="

    secondBlock = messageStart[:16] + USERDATA

    mask = xor_two_str(codeInjection, secondBlock).encode()
    injLength = len(codeInjection)
    mask = mask[injLength:]

    newCiphertext = bytes(a ^ b for a, b in zip(mask, ciphertext))

    return iv + newCiphertext


def main():
    print("Now testing normally")
    line = submit()
    print(verify(line))

    print("\nNow testing with code injection")
    line = submit()
    line = addAdmin(line)
    print(verify(line))

main()