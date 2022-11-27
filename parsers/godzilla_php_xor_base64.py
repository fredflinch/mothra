import re
import base64
import urllib.parse
import zlib
import hashlib

class decoder():
    def __init__(self, key, passwd, payloadname):
        self.key = key 
        self.passwd = passwd
        self.payloadname = payloadname
        self.spec = (hashlib.md5((passwd+key).encode())).hexdigest() 
    
    def decode(self, data):
        if self.passwd+"=" in data:
            try:
                v = ("req", request(data, self.key, self.passwd))
            except: 
                return 0
            if not (v is None or v==0): return v
            else: return 0        
        if "200 OK" in data:
            if self.spec[0:16] in data:
                try:
                    v = ("resp", response(data.split("\r\n")[-1], self.key))
                except:
                    return 0
                if not (v is None or v==0): return v
                else: return 0
        return 0


## function that automatically instanciates decoder class correctly, required to be named automagic ##
def automagic(shell):
    passwd_rex, payloadname_rex, key_rex = r'\$pass=\'(?P<passwd>[\w]{1,})', r'\$payloadName=\'(?P<payloadname>[\w]{1,})', r'\$key=\'(?P<key>[\w]{1,})'
    pR, plR, kR = re.search(passwd_rex, shell), re.search(payloadname_rex, shell), re.search(key_rex, shell)
    if not (None in [pR, plR, kR]):
        key, passwd, payloadname = kR.group('key'), pR.group('passwd'), plR.group('payloadname')
        print("Recovered Keys: \nkey: {}\npassword: {}\npayload name: {}\n".format(key, passwd, payloadname))
        return decoder(key, passwd, payloadname)
    else:
        return 0
        
def shellmethod_encode(val, key):
    decoded_cmd = []
    for i in range(0, len(val)):
        decoded_cmd.append(val[i] ^ ord(key[(i + 1)%len(key)]))
    return decoded_cmd

def response(data, key):
    temp_val = data[16:-16]
    temp_val = urllib.parse.unquote(temp_val)
    temp_val = base64.b64decode(temp_val)
    temp_val = shellmethod_encode(temp_val, key)
    temp_val = zlib.decompress(bytes(temp_val), zlib.MAX_WBITS|16)
    return  ''.join([chr(x) for x in temp_val])

def request(data, key, passwd):
    cmd = data.split(passwd+"=")[1]
    temp_val = urllib.parse.unquote(cmd)
    temp_val = base64.b64decode(temp_val)
    temp_val = shellmethod_encode(temp_val, key)
    temp_val = zlib.decompress(bytes(temp_val), zlib.MAX_WBITS|16)
    return  ''.join([chr(x) for x in temp_val])

if __name__=="__main__":
    # test code
    post_eg = "zgxw0kdTir=Lb46MTc0NTlix32o%2BS%2FGc%2F54V6NRVFXpTXMasRpJHO%2F9Hfv85nv%2BcC4%2FJRkQcxaBmxAryB5UoMUirXPKvE9deJ%2F7y0gSnUwcYsrmDeUgMzgy"
    resp_eg = "33fee7108825bd7fLb46MTc0NTliO0UVw84dEP1+u36duAL2Urb5VflVuA96vv0E/wcADkySnIY3Zu5qofUQMTc0a594b42c808daacc"
    print(decoder("825217459b86c5f3", "zgxw0kdTir", "payload").request(post_eg))
    print(decoder("825217459b86c5f3", "zgxw0kdTir", "payload").response(resp_eg))
