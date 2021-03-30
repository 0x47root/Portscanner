import xml.etree.ElementTree as ET

portscan = {'host': '45.33.32.156', 'scan_type': '-sS', 'open_ports': [22, 80], 'closed_ports': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100], 'filtered_ports': [], 'filtered_or_open_ports': [], 'filtered_or_closed_ports': []}

# creating XML file layout
root = ET.Element("ScanResults")
host = ET.SubElement(root, "host", {"ip": portscan["host"]})
scan_type = ET.SubElement(host, "scan_type")
open_ports = ET.SubElement(host, "open_ports")
closed_ports = ET.SubElement(host, "closed_ports")
filtered_ports = ET.SubElement(host, "filtered_ports")
filtered_or_open_ports = ET.SubElement(host, "filtered_or_open_ports")
filtered_or_closed_ports = ET.SubElement(host, "filtered_or_closed_ports")

# writing scan type
scan = ET.SubElement(scan_type, "scan")
scan.text = portscan["scan_type"]

# create function to fill XML file with ports
def fillXML(port_list, port_element):
    if port_list:
        for p in port_list:
            port = ET.SubElement(port_element, "port")
            port.text = str(p)

# filling XML file with ports
fillXML(portscan["open_ports"], open_ports)
fillXML(portscan["closed_ports"], closed_ports)
fillXML(portscan["filtered_ports"], filtered_ports)
fillXML(portscan["filtered_or_open_ports"], filtered_or_open_ports)
fillXML(portscan["filtered_or_closed_ports"], filtered_or_closed_ports)

# writing XML file
tree = ET.ElementTree(root)
tree.write("portscan.xml")