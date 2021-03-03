import socket

def TCP_connect_scan(target, first_port, last_port):
    last_port += 1
    for port in range(first_port, last_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target,port))
            print(f"Port {port} is open!")
        except:
            print(f"Port {port} is filtered or closed.")

def UDP_scan(target, first_port, last_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    last_port += 1
    for port in range(first_port, last_port):
        try:
            data = "Hello"
            s.sendto(data, (target, port))
            s.settimeout(0)
            print((s.recvfrom(1024)))
            break
        except:
            print("UDP scan error")

#TCP_connect_scan('192.168.11.130', 1330, 1400)
UDP_scan("192.168.11.130", 1332, 1334)