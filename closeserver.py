import sys
if len(sys.argv) != 2:
    print "Correct usage: script, DDC node number"
    exit()

import socket
import hashlib
from Crypto.Cipher import AES

sharedDDCKey=hashlib.md5("sharedKDCpassword").hexdigest()
publicAES = AES.new(sharedDDCKey,AES.MODE_CBC,"1234567890abcdef")

s = socket.socket()
port = 9000+int(sys.argv[1])
s.connect(('127.0.0.1', port))
m = "exit::0::"
if len(m)%16!=0:
    m=m+'x'*(16-len(m)%16)
m=publicAES.encrypt(m)
s.send(m)
s.close()
