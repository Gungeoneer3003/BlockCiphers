from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

def padding(data):
    l = AES.block_size - (len(data) % AES.block_size)
    padded_data = bytes([l]) * l
    return data + padded_data

def unpadding(data):
    data_size = len(data)
    padding_count = data[-1]
    return data[:-padding_count]


KEY = get_random_bytes(16) # 16 byte randomly generated pass
with open('keyFile2.txt', 'wb') as keyFile:
    keyFile.write(KEY)
IV = get_random_bytes(16) #Key is 16 bytes, so this should be 16 bytes

#Hard coded user data to allow easier manipulation, capitalized for 'sudo-const' consistency
USERDATA = "You're the man now, dog"
INPUTFLAG = False

def submit():
    if(INPUTFLAG):
        plaintext = input("Enter a line: ")
    else:
        plaintext = USERDATA

    cleaned = plaintext.replace(';', '%3B').replace('=', '%3D')
    joined = ''.join(["userid=456; userdata=", cleaned, ";session-id=31337"])

    global IV
    cipher = AES.new(KEY, AES.MODE_CBC)
    IV = cipher.iv

    #print(joined)

    ciphertext = cipher.encrypt(padding(joined.encode()))
    return ciphertext

def verify(line):
    #16 should maybe be a variable name
    ciphertext = line

    cipher = AES.new(KEY, AES.MODE_CBC, IV)

    # Decrypt line
    paddedPlaintext = cipher.decrypt(ciphertext)
    #print(paddedPlaintext)

    plaintext = unpadding(paddedPlaintext).decode(errors="ignore")
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

    if(INPUTFLAG):
        plaintext = input("What was the original input: ")
    else:
        plaintext = USERDATA

    cleaned = plaintext.replace(';', '%3B').replace('=', '%3D')
    joined = ''.join(["userid=456; userdata=", cleaned, ";session-id=31337"]).encode()
    originalText = pad(joined, AES.block_size)

    secondMask = bytes(a ^ b for a, b in zip(originalText[-16:], firstMask))

    ciphertext = line[:-32]
    secondLastChunk = line[-32:-16]
    lastChunk = line[-16:]

    newSecondLast = bytes(a ^ b for a, b in zip(secondLastChunk, secondMask))

    return ciphertext + newSecondLast + lastChunk




def main():
    print("Now testing normally")
    line = submit()
    print(verify(line))

    print("\nNow testing with code injection")
    line2 = submit()
    line2 = addAdmin(line2)
    print(verify(line2))

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