"""
This code is written by 0x47root and conducts a portscan.
This is the main file. Separate other files are imported for the code to work.
For more information about the functionality of the code, see README.md.
"""
import ipaddress
import pyfiglet
import json
# Importing self-written files:
import portscans
import SQL
import XML

# Defining functions:
def create_banner():
    """This function prints a banner for the CLI."""
    return pyfiglet.figlet_format("PORT SCANNER") + (70 * "-") + "\n" + "By 0x47root\n" + (70 * "-")

def ask_scantype():
    """This function asks the user which scan type to conduct and returns the scan type."""
    scan_type = input("Please enter scan type (-sT, -sU, -sS or -sX): ")
    while scan_type not in ['-sT', '-sU', '-sS', '-sX']:
        scan_type = input("Wrong input, please enter one of the given options (-sT, -sU, -sS or -sX): ")
    return scan_type

def ask_host():
    """This function asks the user which IPv4 address to scan and returns the target IPv4 address."""
    target = input("Please specify the IP-address to scan: ")
    while True:
        try:
            ipaddress.IPv4Address(target)
            break
        except ipaddress.AddressValueError:
            target = input("AddressValueError: Please specify a correct IPv4 address: ")
    return target

def ask_first_port():
    """This function asks the user the first port to scan in port range and returns the port."""
    while True:
        try:
            first_port = int(input("Please specify the first port in port range: "))
            while first_port not in range(1, 65536):
                first_port = int(input("Wrong number, please specify a single port between 1 and 65535: "))
            break
        except ValueError:
            print("ValueError: It has to be an integer.")
    return first_port

def ask_last_port(first_port):
    """This function asks the user the last port to scan in port range and returns the port."""
    while True:
        try:
            last_port = int(input("Please specify the last port in port range: ")) + 1
            while last_port not in range(1, 65536):
                last_port = int(input("Wrong input, please specify a single port between 1 and 65535: ")) + 1
            while last_port <= first_port:
                last_port = int(input("Please enter a number that is equal or higher than the first: ")) + 1
            break
        except ValueError:
            print("ValueError: It has to be an integer.")
    return last_port

def ask_output():
    """This function asks the user how to output the results and returns the answer."""
    output = input("Do you want to save the output to a file? (y/n): ")
    while output not in ['y', 'n']:
        output = input("Please enter a 'y' or a 'n': ")
    if output == 'y':
        save_output = input("Do you want to save the results to JSON or XML?: ")
        while save_output not in ['JSON', 'XML', 'json', 'xml']:
            save_output = input("Please enter 'JSON' or 'XML'?: ")
    else:
        save_output = False
    return save_output

def create_dict(target, scan_type):
    """This function creates a dictionary to store the scan results."""
    portscan = {}
    portscan['host'] = target
    portscan['scan_type'] = scan_type
    portscan['open_ports'] = []
    portscan['closed_ports'] = []
    portscan['filtered_ports'] = []
    portscan['filtered_or_open_ports'] = []
    portscan['filtered_or_closed_ports'] = []
    return portscan

def writeToJSON(portscan):
    """This function writes the scan results to a JSON file."""
    with open("portscan.json", "w") as outfile:
        json.dump(portscan, outfile)

# Defining a main function to keep an organized code:
def main():
    # Creating the banner:
    print(create_banner())

    # Asking for user input:
    scan_type = ask_scantype()
    target = ask_host()
    first_port = ask_first_port()
    last_port = ask_last_port(first_port)
    save_output = ask_output()

    # Creating the dictionary to store scan results:
    portscan = create_dict(target, scan_type)

    # Check which scan to conduct and execute scan:
    if scan_type == "-sT":
        portscans.TCP_connect_scan(target, first_port, last_port, portscan)
    elif scan_type == "-sU":
        portscans.UDP_scan(target, first_port, last_port, portscan)
    elif scan_type == "-sS":
        portscans.TCP_SYN_scan(target, first_port, last_port, portscan)
    elif scan_type == "-sX":
        portscans.XMAS_scan(target, first_port, last_port, portscan)

    # Writing the scan results to a XML or JSON file, if specified:
    if save_output:
        if save_output in ['xml', 'XML']:
            XML.writeToXML(portscan)
        elif save_output in ['json', 'JSON']:
            writeToJSON(portscan)

    # Writing the scan results to a SQLite database file:
    SQL.writeToSQLite(portscan)

# Executing the main function:
if __name__ == '__main__':
    main()
