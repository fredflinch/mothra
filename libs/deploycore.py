import paramiko, os, subprocess

SUPPORTED_GOARCH = ["386", "amd64", "amd64p32", "arm", "arm64", "arm64be", "armbe", "loong64", "mips", "mips64", "mips64le", "mips64p32", "mips64p32le", "mipsle", "ppc", "ppc64", "ppc64le", "riscv", "riscv64", "s390", "s390x", "sparc", "sparc64", "wasm"]
SUPPORTED_GOOS = ["aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "js", "linux", "netbsd", "openbsd", "plan9", "solaris", "windows"]

def createconnection(host, user, auth, contype, mode='key'):
    ssh = paramiko.SSHClient()
    if mode=='key':
        key = paramiko.RSAKey.from_private_key_file(auth)
        ssh.connect(host, username=user, pkey=key)
    else:
        ssh.connect(host, username=user, password=auth)
    if contype == 'sftp': 
        return ssh.open_sftp()
    elif contype == 'ssh': 
        return ssh

class filetransfer():
    def __init__(self, host, user, auth, mode='key'):
        self.sftpconn = createconnection(host, user, auth, 'sftp', mode)
    
    def put(self, lfile, rfile):
        self.sftpconn.put(lfile, rfile)
    
    def get(self, lfile, rfile):
        self.sftpconn.get(rfile, lfile)

class commandexec():
    def __init__(self, host, user, auth, mode='key'):
        self.sshconn = createconnection(host, user, auth, 'ssh', mode)
    
    def runcmd(self, cmd):
        _, stdout, _ = self.sshconn.exec_command(cmd)
        return stdout 

def docompile(ball, arch, opsys='linux'):
    if not (arch in SUPPORTED_GOARCH and opsys in SUPPORTED_GOOS):
        print("[!] Unsupported compile destination [!]")
        return 
    os.environ['GOOS'] = opsys
    os.environ['GOARCH'] = arch
    ## build command ##
    buildcmd = "go build -o ./mothraballs/build/{arch}{plat}-{ball} ./motraballs/src/{ball}.go".format(ball=ball, arch=arch, plat=opsys)
    p = subprocess.run(buildcmd)
    print(p.returncode)



if __name__=="__main__":
    docompile('scan', 'amd64')
