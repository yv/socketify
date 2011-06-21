import socket
import sys
from getopt import getopt

BUF_SIZE=128
BUF_NET=32768

tcp_addr='localhost'
tcp_port=4445

(opts,args)=getopt(sys.argv[1:],'b:p:')
for k,v in opts:
    if k=='-b':
        tcp_addr=v
    elif k=='-p':
        tcp_port=int(v)

if args:
    f=file(args[0])
else:
    f=sys.stdin

sock=socket.create_connection((tcp_addr,tcp_port))
response=[]

while True:
    l=f.read(BUF_SIZE)
    if l=='':
        break
    sock.send(l)
    try:
        l2=sock.recv(BUF_NET,socket.MSG_DONTWAIT)
        response.append(l2)
    except socket.error, ex:
        if ex.errno==11:
            pass
        else:
            raise
sock.shutdown(socket.SHUT_WR)
while True:
    l2=sock.recv(1024)
    response.append(l2)
    if l2=='':
        break
sys.stdout.write(''.join(response))
