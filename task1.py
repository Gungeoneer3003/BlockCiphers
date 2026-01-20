from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import sys

#Commandline arguments (should check error-handling?)

image_name = sys.argv[1]

# CONST_IMAGE_NAME = 'cp-logo.bmp' #not actually const, be careful!

key = get_random_bytes(16) # 16 byte randomly generated pass
with open('keyFile1.txt', 'wb') as keyFile:
    keyFile.write(key)

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
encryptedECB = cipherECB.encrypt(pad(imagedata, AES.block_size))
encryptedCBC = cipherCBC.encrypt(pad(imagedataCopy, AES.block_size))

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