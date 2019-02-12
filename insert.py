import pymysql.cursors
import hashlib
user = ['client'+str(i) for i in xrange(1,7)]
password=["12345678", "1234qwer", "password", "p@sswrd1", "password", "qwerty1$"]
server=["fserverA", "fserverB"];
serverpass=["BigP@s$wRd","An0t#eRpSwD"]

key = [hashlib.sha256(password[i]).hexdigest() for i in xrange(6)]
keymd5 = [hashlib.md5(password[i]).hexdigest() for i in xrange(6)]
skey = [hashlib.md5(i).hexdigest() for i in serverpass]
def insertID(i):
    connection = pymysql.connect(host='localhost',user='root',password='root',db='test1',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor)
    try:
        with connection.cursor() as cursor:
            # Read a single record
            sql = "INSERT into `client`(`user`,`key`) VALUES(%s,%s)"
            cursor.execute(sql, (user[i],keymd5[i]))
            connection.commit()
    finally:
        connection.close()
def insertServer(i):
    connection = pymysql.connect(host='localhost',user='root',password='root',db='test1',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor)
    try:
        with connection.cursor() as cursor:
            # Read a single record
            sql = "INSERT into `server`(`user`,`key`) VALUES(%s,%s)"
            cursor.execute(sql, (server[i],skey[i]))
            connection.commit()
    finally:
        connection.close()
for i in xrange(6):
    insertID(i)
for i in xrange(2):
    insertServer(i)
