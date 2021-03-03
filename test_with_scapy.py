from scapy.all import *

ip = "192.168.178.237"
openp = []
filterdp = []
common_ports = {80}

def is_up(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=10)
    if resp == None:
        return False
    else:
        return True

def probe_port(ip, port, result = 1):
    src_port = RandShort()
    try:
        p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='F')
        resp = sr1(p, timeout=2) # Sending packet
        if str(type(resp)) == "<type 'NoneType'>":
            result = 1
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x14:
                result = 0
            elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                result = 2
    except Exception as e:
        pass
    return result

if is_up(ip):
    for port in common_ports:
        print(port)
        response = probe_port(ip, port)
        if response == 1:
            openp.append(port)
        elif response == 2:
            filterdp.append(port)
    if len(openp) != 0:
        print("Possible Open or Filtered Ports:")
        print(openp)
    if len(filterdp) != 0:
        print("Possible Filtered Ports:")
        print(filterdp)
    if (len(openp) == 0) and (len(filterdp) == 0):
        print("Sorry, No open ports found.!!")
else:
    print("Host is Down")