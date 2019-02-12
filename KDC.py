import pymysql.cursors
import sys
import hashlib
import random
import string
from Crypto.Cipher import AES
KDCkey=hashlib.md5("strongKDCpassword").hexdigest()
signature="authorizedby kdc"
KDCpublic=hashlib.md5("sharedKDCpassword").hexdigest()
def validateUser(user, pswd):

    key=hashlib.md5(pswd).hexdigest()
    ret=0
    kdcaes = AES.new(KDCkey, AES.MODE_CBC, 'This is an IV456')
    aes = AES.new(key, AES.MODE_CBC, 'This is an IV456')

    connection = pymysql.connect(host='localhost',user='root',password='root',db='test1',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor)
    try:

        with connection.cursor() as cursor:
            # Read a single record

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
                ciphertext = kdcaes.encrypt(m)
                ciphertext=ciphertext.encode('base64','strict')
                m=ciphertext+'::'+user+'::'+key+"::"
                if len(m)%16!=0:
                    m=m+'x'*(16-len(m)%16)
                ciphertext = aes.encrypt(m)
                ret = ciphertext.encode('base64','strict')
            else:
                print "Invalid username and/or password"
                ret= -1
    finally:
        connection.close()
        print "Sending Ticket Granting Ticket"
        return ret
def validateTicket(auth):
    kdcaes = AES.new(KDCkey, AES.MODE_CBC, 'This is an IV456')

    auth = auth.decode('base64','strict')
    auth = kdcaes.decrypt(auth)
    sign,userclass,extra= auth.split("::")
    if sign==signature:
        print "TGT verified Successfully"
        return (1,userclass)
    else:
        print "Ticket forgery detected"
        return (0,"")
def validateRequest(ticket, filename, source):
    kdcaespublic= AES.new(KDCpublic, AES.MODE_CBC, 'This is an IV456')
    ticket = ticket.decode('base64','strict')
    m = kdcaespublic.decrypt(ticket)
    authenticator,user,key,extra = m.split("::")
    caes = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    auth = authenticator
    valid,userclass = validateTicket(auth)
    ret=0
    if valid==0:
        return -1
    connection = pymysql.connect(host='localhost',
                                 user='root',
                                 password='root',
                                 db='test1',
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)

    try:
        with connection.cursor() as cursor:
            # Read a single record
            sql = "SELECT count(`file`) FROM `file_class` WHERE `file`=%s AND `class`=%s AND `server`=%s"
            cursor.execute(sql, (filename,userclass,source))
            result = cursor.fetchone()
            if result["count(`file`)"]==1:
                print "User Privileges matched for Requested file"
                sql = "SELECT `key` FROM `server` WHERE `user`=%s"
                cursor.execute(sql, (source))
                result = cursor.fetchone()
                skey = result["key"]
                saes = AES.new(skey, AES.MODE_CBC, 'This is an IV456')
                Scskey = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32))
                Sskey = saes.encrypt(Scskey)
                Sskey = Sskey.encode('base64','strict')
                m=Scskey+'::'+Sskey+"::"
                if len(m)%16!=0:
                    m=m+'x'*(16-len(m)%16)
                ciphertext = caes.encrypt(m)
                ret = ciphertext.encode('base64','strict')
            else:
                print "permission denied"
                ret= -1
    finally:
        connection.close()
        return ret
