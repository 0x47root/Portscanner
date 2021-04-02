"""
This file creates a XML object, writes the scanned ports to this object
and writes the object to a XML file.
"""
import xml.etree.ElementTree as ET

def writeToXML(portscan_variable):
    """This function writes the scan results to a XML file."""

    # Creating the XML object layout:
    root = ET.Element("ScanResults")
    host = ET.SubElement(root, "host", {"ip": portscan_variable["host"]})
    scan_type = ET.SubElement(host, "scan_type")
    open_ports = ET.SubElement(host, "open_ports")
    closed_ports = ET.SubElement(host, "closed_ports")
    filtered_ports = ET.SubElement(host, "filtered_ports")
    filtered_or_open_ports = ET.SubElement(host, "filtered_or_open_ports")
    filtered_or_closed_ports = ET.SubElement(host, "filtered_or_closed_ports")

    # Writing the scan type:
    scan = ET.SubElement(scan_type, "scan")
    scan.text = portscan_variable["scan_type"]

    # Creating a separate function to fill XML object with the scanned ports:
    def fillXML(port_list, port_element):
        if port_list:
            for p in port_list:
                port = ET.SubElement(port_element, "port")
                port.text = str(p)

    # Filling the XML object with scanned ports:
    fillXML(portscan_variable["open_ports"], open_ports)
    fillXML(portscan_variable["closed_ports"], closed_ports)
    fillXML(portscan_variable["filtered_ports"], filtered_ports)
    fillXML(portscan_variable["filtered_or_open_ports"], filtered_or_open_ports)
    fillXML(portscan_variable["filtered_or_closed_ports"], filtered_or_closed_ports)

    # Writing the XML object to a XML file:
    tree = ET.ElementTree(root)
    tree.write("portscan.xml")
