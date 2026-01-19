from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sys

key = get_random_bytes(16) # 16 byte randomly generated pass
with open('keyFile2.txt', 'wb') as keyFile:
    keyFile.write(key)

#Hard coded user data to allow easier manipulation
userdata = "You're the man now, dog"

def submit():
    #plaintext = input("Enter a line: ")
    plaintext = userdata
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
    paddedPlaintext = cipher.decrypt(ciphertext)
    print(paddedPlaintext)

    plaintext = unpad(paddedPlaintext, AES.block_size).decode()
    print(plaintext)

    #Redundant split for readability
    if (";admin=true;" in plaintext):
        return True #Normally, it should never reach here
    else:
        return False

'''
This method will work by messing with the ciphertext to
1. Add one more block since we can use the last one to write in the new one
2. Make a mask and add the proper bits for admin
3. Do the math and add the remaining padding to the mask
4.  
(This will mean that the original padding and 2nd to last block will be garbage)
This will work because every block has to be 16 bytes
'''

def addAdmin(line):
    codeInjection = ";admin=true;".encode()
    padLength = 16 - (len(codeInjection) & 15)
    padBytes = bytes([padLength] * padLength)
    firstMask = codeInjection + padBytes

    plaintext = userdata
    cleaned = plaintext.replace(';', '%3B').replace('=', '%3D')
    joined = ''.join(["userid=456; userdata=", cleaned, ";session-id=31337"]).encode()
    originalText = pad(joined, AES.block_size)
    secondMask = bytes(a ^ b for a, b in zip(originalText[-16:], firstMask))

    iv = line[:16]
    ciphertext = line[16:-32]
    secondLastChunk = line[-32:-16]
    lastChunk = line[-16:]

    newSecondLast = bytes(a ^ b for a, b in zip(secondLastChunk, secondMask))

    return iv + ciphertext + newSecondLast + lastChunk


def main():
    print("Now testing normally")
    line = submit()
    print(verify(line))

    print("\nNow testing with code injection")
    line5 = submit()

    line5 = addAdmin(line5)
    print(verify(line5))

main()


'''
    newLine = line
    iv =  newLine[16:]
    ciphertext =  newLine
    codeInjection = ";admin=true;".encode()

    newBlocks = bytearray(31)
    for i in range(len(newBlocks)):
        newBlocks[i] = 0

    change = 'A'.encode()

    test = ciphertext[-16].to_bytes(1, "big")
    result = bytes(a ^ b for a, b in zip(change, test))
    print(hex(test[0]), hex(change[0]), hex(result[0]))

    newCiphertext = ciphertext + result
    
    
    injLength = len(codeInjection)
    padLength = 16 - (injLength & 15)

    newBlocks[:injLength] = codeInjection.encode()
    newBlocks[:padLength] = bytes([padLength]) * padLength

'''