import os,binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cipher1 = "fe0f42ae809fe1e2ff5b59725ef52048"
cipher5 = "ca6889853e3ddfaf621b87ee4966e274"
plain1 = "Counterclockwise"

def expandKey(shortKey):    
    shortKeyval1=shortKey[0]
    shortKeyval2=shortKey[1]
    #Last four bits are ignored
    shortKeyval3=shortKey[2]&0xF0
    
    ByteA=shortKeyval1.to_bytes(1,"big")
    ByteB=shortKeyval2.to_bytes(1,"big")
    ByteC=shortKeyval3.to_bytes(1,"big")
    hexByte1=0x94
    Byte1=hexByte1.to_bytes(1,"big")
    hexByte2=0x5a
    Byte2=hexByte2.to_bytes(1,"big")
    hexByte3=0xe7
    Byte3=hexByte3.to_bytes(1,"big")
    
    longKey=bytearray(ByteA)    
    longKey.extend(Byte1)
    longKey.extend(ByteB)    
    longKey.extend(Byte2)
    
    for i in range(4,9):        
        hexByte=(longKey[i-1]+longKey[i-4])%257
        if (hexByte==256):
            hexByte=0
        Byte=hexByte.to_bytes(1,"big")              
        longKey.extend(Byte)
    longKey.extend(ByteC)   
    longKey.extend(Byte3)
    for i in range(11,16):
        hexByte=(longKey[i-1]+longKey[i-4])%257
        if (hexByte==256):
            hexByte=0
        Byte=hexByte.to_bytes(1,"big")              
        longKey.extend(Byte)    
    
    return longKey




for num in range(2**24):
    shortKeyBytes = os.urandom(3)
    shortKey=bytearray(shortKeyBytes)
    #Expand key to 128 bits
    key=expandKey(shortKey)
    iv=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    encryptor = cipher.encryptor()
    message_bytes=plain1.encode('UTF-8')
    secretcipher=encryptor.update(message_bytes)+encryptor.finalize()
    if cipher == cipher1:
        print("Key :"+key)
        secretcipher = bytes.fromhex(cipher5)
        plain=decryptor.update(secretcipher)+decryptor.finalize()
        print("secret plain text: "+plain.decode('UTF-8'))
        break
