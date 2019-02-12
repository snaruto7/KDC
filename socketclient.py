import sys
if len(sys.argv) != 2:
    print "Correct usage: script, DDC node number"
    exit()

import socket
import hashlib
from Crypto.Cipher import AES
import random

sharedDDCKey=hashlib.md5("sharedKDCpassword").hexdigest()
publicAES = AES.new(sharedDDCKey,AES.MODE_CBC,"1234567890abcdef")

def readUser():
    user = raw_input("Enter Username: ")
    pswd = raw_input("Enter Passwrd: ")
    return (user,pswd)

def readFileRequest():
    filename = raw_input("Enter name of file to be fetched: ")
    source = raw_input("Enter server name: ")
    return (filename,source)

def encryptCredentials(user,pswd):
    m = "login::"+user+"::"+pswd+"::"
    if len(m)%16!=0:
        m=m+'x'*(16-len(m)%16)
    print m
    m=publicAES.encrypt(m)
    return m

user,pswd=readUser()
key = hashlib.md5(pswd).hexdigest()
requestLogin = encryptCredentials(user,pswd)
iv = Random.new().read(AES.block_size)
clientAES = AES.new(key,AES.MODE_CBC,iv)
s = socket.socket()
port = 9000+int(sys.argv[1])

s.connect(('127.0.0.1', port))
print requestLogin
s.send(requestLogin+"::"+iv)

TGT = s.recv(1024)
TGT = clientAES.decrypt(TGT)
print TGT
s.close()
