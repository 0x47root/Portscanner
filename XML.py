import xml.etree.ElementTree as ET

target = "45.33.32.156"

# variables collecting scanned ports
open = [21,80,443]
closed = [1,2,3,4,5,6,7,8,9,10]
filtered = [11,12,13]
filtered_or_open = [1337]
filtered_or_closed = [889,887]

# creating XML file layout
root = ET.Element("ScanResults")
host = ET.SubElement(root, "host", {"ip": target})
open_ports = ET.SubElement(host, "open_ports")
closed_ports = ET.SubElement(host, "closed_ports")
filtered_ports = ET.SubElement(host, "filtered_ports")
filtered_or_open_ports = ET.SubElement(host, "filtered_or_open_ports")
filtered_or_closed_ports = ET.SubElement(host, "filtered_or_closed_ports")

# create function to fill XML file with ports
def fillXML(port_list, port_element):
    if port_list:
        for p in port_list:
            port = ET.SubElement(port_element, "port")
            port.text = str(p)

# filling XML files with ports
fillXML(open, open_ports)
fillXML(closed, closed_ports)
fillXML(filtered, filtered_ports)
fillXML(filtered_or_open, filtered_or_open_ports)
fillXML(filtered_or_closed, filtered_or_closed_ports)

ET.dump(root)