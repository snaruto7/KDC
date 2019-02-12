import sys
if len(sys.argv) != 2:
    print "Correct usage: script, DDC node number"
    exit()

import socket
import hashlib
from Crypto.Cipher import AES
import pymysql.cursors
import random

s = socket.socket()
print "Socket successfully created"

port = 9000+int(sys.argv[1])
privateDDCKey=hashlib.md5("strongKDCpassword").hexdigest()
signature="authorized by kdc"
sharedDDCKey=hashlib.md5("sharedKDCpassword").hexdigest()
#publicAES = AES.new(sharedDDCKey,AES.MODE_CBC,"1234567890abcdef")
#secretAES = AES.new(privateDDCKey,AES.MODE_CBC,"1234567890abcdef")

def validateUserAndGrantTGT(user, pswd):
    ret=0
    key=hashlib.md5(pswd).hexdigest()
    iv = Random.new().read(AES.block_size)
    clientAES = AES.new(key, AES.MODE_CBC, iv)
    connection = pymysql.connect(host='localhost',user='root',password='root',db='test1',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor)
    with connection.cursor() as cursor:
        sql = "SELECT count(`user`) FROM `client` WHERE `user`=%s AND `key`=%s"
        cursor.execute(sql, (user,key))
        result = cursor.fetchone()
        if result["count(`user`)"]==1:
            print "User Authenticated Successfully"
            sql = "SELECT `class` FROM `client_class` WHERE `user`=%s"
            cursor.execute(sql, (user))
            result2 = cursor.fetchone()
            userclass=result2["class"]
            m=signature+"::"+userclass+"::"
            if len(m)%16!=0:
                m=m+'x'*(16-len(m)%16)
            secretAES = AES.new(privateDDCKey,AES.MODE_CBC,"1234567890abcdef")
            sign = secretAES.encrypt(m)
            m = sign+'::'+user+'::'+key+"::"
            if len(m)%16!=0:
                m=m+'x'*(16-len(m)%16)
            ticket = clientAES.encrypt(m)
            ret = ticket+"::"+iv
        else:
            print "Invalid username and/or password"
            ret= -1
        connection.close()
        print "Sending Ticket Granting Ticket"
        return ret

s.bind(('', port))
print "socket binded to %s" %(port)
s.listen(6)


while True:
    print "socket is listening"
    c, addr = s.accept()
    print 'Got connection from', addr

    req = c.recv(1024)
    req,iv = req.split('::')
    publicAES = AES.new(sharedDDCKey,AES.MODE_CBC,iv)
    m = publicAES.decrypt(req);
    m=m.split("::")
    if m[0]=="login":
        user,pswd=m[1],m[2]
        ticket = validateUserAndGrantTGT(user,pswd)
        c.send(ticket)
    elif m[0]=="exit":
        c.close()
        break;
    c.close()
s.close()
