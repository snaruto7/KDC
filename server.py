import hashlib
from Crypto.Cipher import AES
def fileRequest(message,auth,ticket):
    print "File request reached at File Server"
    key = hashlib.md5("BigP@s$wRd").hexdigest()
    aes = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    #ticket = aes.decrypt(ticket)
