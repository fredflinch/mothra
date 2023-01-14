import re
import base64


class decoder():
    def __init__(self, key):
        self.key = key

    def decode(self, data):
        if "{\""+self.key+"\":" in data:
            return ("req", decode_request(data.split("\r\n")[-1]))
        if "200 OK" in data:
            holder = decode_response(data.split("\r\n")[-1])
            if holder is not None:
                return ("resp", holder)
        return 0
        
def automagic(shell):
        keymatch = re.search(r'Buffer\.from\(req\.body\[\'(?P<key>[^\']*)\'\]', shell)
        if keymatch is not None:
            return decoder(keymatch['key'])
        else: return None
    
def decode_request(data):    
    return base64.b64decode(data.split(": ")[1][1:-2].encode()).decode()

def decode_response(data):
    try:
        resp_dat = base64.b64decode(data.encode() + b'==').decode('utf-8')
        return resp_dat
    except: 
        return None   
        

