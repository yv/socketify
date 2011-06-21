import socket
import sys

BUF_SIZE=128
BUF_NET=32768
sock=socket.create_connection(('localhost','4445'))

if len(sys.argv) > 1:
    f=file(sys.argv[1])
else:
    f=sys.stdin
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
