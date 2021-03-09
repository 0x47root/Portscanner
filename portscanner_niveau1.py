import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
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
    last_port += 1
    # This script checks if the host replies with an ICMP host-unreachable reply
    # If no reply is received, the port can be open or filtered.
    for port in range(first_port, last_port):
        ans = sr1(IP(dst=target)/UDP(dport=port), timeout=5, verbose=0)
        # A timeout of 5 seconds is used to adjust
        # for latent responses that result from ICMP host-unreachable rate limiting
        time.sleep(1)
        if ans == None:
            print(f"Port {port} is open or filtered!")
        else:
            print(f"Port {port} is closed")

def TCP_SYN_scan(target, first_port, last_port):
    last_port += 1
    for port in range(first_port, last_port):
        ans = sr1(IP(dst=target)/TCP(dport=port), timeout=1, verbose=0)
        # If the timeout value is not specified when this function is used against a unresponsive host,
        # the function will continue indefinitely
        if ans == None:
            print(f"Port {port} is filtered!")
        else:
            if int(ans[TCP].flags) == 18: # 18 means SYN (2) + ACK (16)
                print(f"Port {port} is open!")
            #elif (int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                #print(f"Port {port} is filtered!")
            else:
                print(f"Port {port} is closed")

def XMAS_scan(target, first_port, last_port):
    last_port += 1
    for port in range(first_port, last_port):
        ans = sr1(IP(dst=target)/TCP(dport=port, flags='FPU'), timeout=2, verbose=0) # PSH, FIN and URG
        if ans == None:
            print(f"Port {port} is open!")
        elif ans.haslayer(TCP):
            if int(ans[TCP].flags) == 20: # 20 means RST (4) + ACK (16)
                print(f"Port {port} is closed")
            else:
                print(f"Port {port} is filtered")

#TCP_connect_scan('45.33.32.156', 514, 514)
#UDP_scan('45.33.32.156', 120, 125)
#TCP_SYN_scan('45.33.32.156', 514, 514)
XMAS_scan('45.33.32.156', 20, 80)