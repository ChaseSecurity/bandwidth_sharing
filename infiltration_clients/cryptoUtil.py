#!/usr/bin/python
import os, sys
from Crypto.Cipher import AES
from Crypto import Random
import base64
#generate keys
def genKey(len): #bytes
    #key = os.urandom(len)
    rndfile = Random.new()
    key = rndfile.read(16)
    return key

def decryptAES_CBCMsg(keyStr, cipherText):
    responseTxt = base64.b64decode(cipherText)
    print('aes', responseTxt)
    iv = responseTxt[:16]
    cipherText = responseTxt[16:]
    print('keyStr',keyStr)
    key = bytes.fromhex(keyStr)
    print('key', key)
    #key = keyStr.decode("hex")
    #key = keyStr.decode("hex")
    aesObj = AES.new(key, AES.MODE_CBC, iv)
    plaintext = aesObj.decrypt(cipherText)
    plaintext = plaintext.decode('utf-8')
    return plaintext.strip("\x02")

def encryptAES_CBCMsg(key, iv,  plaintext):
    #padding before encryption
    sizeOfPlain = len(plaintext)
    print("orginal length is ", sizeOfPlain)
    blockSize = AES.block_size
    paddingLen = blockSize - (sizeOfPlain % blockSize)
    plaintext += " " * paddingLen
    print("plaintext length after padding is ", len(plaintext))
    aesObj = AES.new(key, AES.MODE_CBC, iv)
    cipherText = aesObj.encrypt(plaintext)
    return cipherText

if __name__ == "__main__":
    #key = genKey(16)
    #print("new key is {}".format(key.encode("hex")))
    #iv = genKey(16)
    #print("iv is {}".format(iv.encode("hex")))
    #plainMsg = "I miss you pretty much"
    #encrypted = encryptAES_CBCMsg(key, iv, plainMsg)
    #decrypted = decryptAES_CBCMsg(key, iv, encrypted)
    #print("encrypted is **{}**".format(encrypted.encode("hex")))
    #print("decrypted is {}".format(decrypted))
    import requests
    import base64
    import json
    url = "http://rpaas.site/test.php"
    response = requests.get(url)
    print(response.text)
    keyStr = "1f137cfa6927645c8208332ee0cd906b"
    decrypted = decryptAES_CBCMsg(keyStr, response.text)
    print(json.loads(decrypted))
