import socket
import sys
from datetime import datetime
import pyfiglet

# Banner toevoegen aan programma
ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)
print("A port scanner by 0x47root")
print("-" * 50)

target = input("Please specify the IP-address to scan: ")
first_port = int(input("Please specify the first port in the range: "))
last_port = int(input("Please specify the last port in the range: ")) + 1

if target: # hier later een regex plaatsen om IP address te checken
    target = target
else:
    print("Invalid target!")

# De target en tijd weergeven
print("-" * 50)
print("Scanning Target: " + target)
print("Scanning started at:" + str(datetime.now()))
print("-" * 50)

try:

    # dit is de daadwerkelijke portscan
    for port in range(first_port, last_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        # returns an error indicator
        result = s.connect_ex((target, port))
        if result == 0:
            print("Port {} is open".format(port))
        s.close()

except KeyboardInterrupt:
    print("\n Exitting Program !!!!")
    sys.exit()
except socket.gaierror:
    print("\n Hostname Could Not Be Resolved !!!!")
    sys.exit()
except socket.error:
    print("\ Server not responding !!!!")
    sys.exit()