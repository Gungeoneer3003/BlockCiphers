from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from dataclasses import dataclass

key = b'thisisasecretpas' # 16 byte pass

cipher = AES.new(key, AES.MODE_ECB)

bitmap_header = bytes(54)

file = open("cp-logo.bmp", "rb")
bitmap_header = file.read(54)



