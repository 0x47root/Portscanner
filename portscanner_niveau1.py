import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time

def TCP_connect_scan(target, first_port, last_port):
    last_port += 1
    s_port = RandShort()
    for port in range(first_port, last_port):
        ans = sr1(IP(dst=target)/TCP(sport=s_port, dport=port,flags="S"), timeout=1, verbose=0)
        if ans == None:
            print(f"Port {port} is closed")
        elif ans.haslayer(TCP):
            if ans.getlayer(TCP).flags == 0x12: # 0x12 = 18 = 16 + 2 = ACK + SYN
                rst = sr(IP(dst=target)/TCP(sport=s_port, dport=port,flags="AR"), timeout = 1, verbose=0)
                print(f"Port {port} is open!")
            elif ans.getlayer(TCP).flags == 0x14: # 0x14 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed")

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
        ans = sr1(IP(dst=target)/TCP(dport=port,flags="S"), timeout=1, verbose=0)
        # If the timeout value is not specified when this function is used against a unresponsive host,
        # the function will continue indefinitely
        if ans == None:
            print(f"Port {port} is filtered!")
        elif ans.haslayer(TCP):
            if ans.getlayer(TCP).flags == 0x12: # 0x12 = 18 = 16 + 2 = ACK + SYN
                rst = sr(IP(dst=target)/TCP(dport=port,flags="R"), timeout = 1, verbose=0)
                print(f"Port {port} is open!")
            elif ans.getlayer(TCP).flags == 0x14: # 0x12 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed")
            elif ans.haslayer(ICMP):
                if int(ans.getlayer(ICMP).type)==3 and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered!")

def XMAS_scan(target, first_port, last_port):
    last_port += 1
    for port in range(first_port, last_port):
        ans = sr1(IP(dst=target)/TCP(dport=port,flags="FPU"), timeout=1, verbose=0) # FIN, PSH and URG
        if ans == None:
            print(f"Port {port} is filtered or open!")
        elif ans.haslayer(TCP):
            if ans.getlayer(TCP).flags == 0x14: # 0x14 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed.")
            elif ans.haslayer(ICMP):
                if int(ans.getlayer(ICMP).type)==3 and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered.")

#TCP_connect_scan('192.168.178.1', 1, 100)
UDP_scan('45.33.32.156', 1, 100)
#TCP_SYN_scan('45.33.32.156', 514, 514)
#XMAS_scan('45.33.32.156', 20, 80)