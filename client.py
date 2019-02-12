from KDC import validateUser
from KDC import validateRequest
from server import fileRequest
import hashlib
import time
from Crypto.Cipher import AES
kdckey=hashlib.md5("sharedKDCpassword").hexdigest()
aesx = AES.new(kdckey, AES.MODE_CBC, 'This is an IV456')

def readUser():
    user = raw_input("Enter Username: ")
    pswd = raw_input("Enter Passwrd: ")
    return (user,pswd)
def readFileRequest():
    filename = raw_input("Enter name of file to be fetched: ")
    source = raw_input("Enter server name: ")
    return (filename,source)


user,pswd=readUser()
key=hashlib.md5(pswd).hexdigest()
aes = AES.new(key, AES.MODE_CBC, 'This is an IV456')

ticket=validateUser(user,pswd)

TGT = ticket.decode(encoding='base64',errors='strict')
reqTGT = aes.decrypt(TGT)

filename,source=readFileRequest()

TGTx = aesx.encrypt(reqTGT)
TGTx = TGTx.encode(encoding='base64',errors='strict')

ticket=validateRequest(TGTx,filename,source)
TGS = ticket.decode(encoding='base64',errors='strict')
reqTGS = aes.decrypt(TGS)

sessionkey,serverkey,extra = reqTGS.split("::")
sessionaes = AES.new(sessionkey, AES.MODE_CBC, 'This is an IV456')
m = str(time.time())
if len(m)%16!=0:
    m=m+'x'*(16-len(m)%16)
sessionaes.encrypt(m)
fileRequest(m,TGTx,serverkey)
