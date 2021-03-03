import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = '192.168.178.237'

def portscan(port):
    try:
        s.connect((server,port))
        return True
    except:
        return False

for x in range(70,81):
    if portscan(x):
        print(f"Port {x} is open!")
    else:
        print(f"Port {x} is closed.")