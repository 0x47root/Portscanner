from scapy.all import *
import socket
import time

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
    for port in range(first_port, last_port):
        ans = sr1(IP(dst=target) / UDP(dport=port), timeout=5, verbose=0)
        #time.sleep(1)
        if ans == None:
            print(f"Port {port} is open!")
        else:
            print(f"Port {port} is closed")

#TCP_connect_scan('192.168.11.130', 1330, 1400)
UDP_scan("131.100.154.250", 52, 55)