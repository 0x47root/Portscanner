import unittest
import os.path
import os

# Import from own files.
from main import *
from portscans import *
from SQL import *
from XML import *

class MainTests(unittest.TestCase):

    def test_create_banner(self):
        """The function should create a banner."""
        self.assertIsNotNone(create_banner())

    def test_ask_scantype(self):
        """The function should ask the user for input and output -sT, -sU, -sS or -sX."""
        self.assertIn(ask_scantype(), ['-sT', '-sU', '-sS', '-sX'])

    def test_ask_host(self):
        """The function should ask the user for input and return a string."""
        self.assertIsInstance(ask_host(), str)

    def test_ask_first_port(self):
        """The function should ask the user for input and output an integer between 1 and 65535."""
        self.assertIn(ask_first_port(), range(1, 65536))

    def test_ask_last_port(self):
        """
        The function should ask the user for input and output an integer between 1 and 65535.
        Also the integer has to be higher than or equal to the first port.
        """
        self.assertIn(ask_last_port(first_port=1), range(1, 65536))

    def test_ask_output(self):
        """
        The function should ask the user whether they want to safe the scan results or not.
        Finally the function should output 'JSON', 'XML', 'json', 'xml' or False.
        """
        self.assertIn(ask_output(), ['JSON', 'XML', 'json', 'xml', False])

    def test_create_dict(self):
        """
        The function should create a dictionary to store the scan results in.
        """
        self.assertIsInstance(create_dict(target='45.33.32.156', scan_type='-sS'), dict)

    def test_TCP_connect_scan(self):
        """
        The function should conduct a TCP-Connect scan to a specific IP address and write the results to
        the dictionary with the name 'portscan'. While testing, the port range 20-25 is used on 'scanme.nmap.org'.
        Port 22 should be open and the other ports should be filtered or closed.
        """
        portscan = create_dict(target='45.33.32.156', scan_type='-sT')
        TCP_connect_scan(target='45.33.32.156', first_port=20, last_port=26, portscan_variable=portscan)
        self.assertEqual(portscan["filtered_or_closed_ports"], [20, 21, 23, 24, 25])
        self.assertEqual(portscan["open_ports"], [22])

    def test_UDP_scan(self):
        """
        The function should conduct a UDP scan to a specific IP address and write the results to
        the dictionary with the name 'portscan'. While testing, the port range 50-55 is used on my own router.
        Port 53 should be open or filtered and the other ports should be closed.
        """
        portscan = create_dict(target='192.168.178.1', scan_type='-sU')
        UDP_scan(target='192.168.178.1', first_port=50, last_port=56, portscan_variable=portscan)
        self.assertEqual(portscan["closed_ports"], [50, 51, 52, 54, 55])
        self.assertEqual(portscan["filtered_or_open_ports"], [53])

    def test_TCP_SYN_scan(self):
        """
        The function should conduct a TCP SYN scan to a specific IP address and write the results to
        the dictionary with the name 'portscan'. While testing, the port range 20-25 is used on 'scanme.nmap.org'.
        Port 21 should be open and the other ports should be closed.
        """
        portscan = create_dict(target='45.33.32.156', scan_type='-sS')
        TCP_SYN_scan(target='45.33.32.156', first_port=20, last_port=26, portscan_variable=portscan)
        self.assertEqual(portscan["closed_ports"], [20, 21, 23, 24, 25])
        self.assertEqual(portscan["open_ports"], [22])

    def test_XMAS_scan(self):
        """
        The function should conduct a TCP XMAS scan to a specific IP address and write the results to
        the dictionary with the name 'portscan'. While testing, the port range 20-25 is used on 'scanme.nmap.org'.
        It should return all ports are open or filtered.
        """
        portscan = create_dict(target='45.33.32.156', scan_type='-sX')
        XMAS_scan(target='45.33.32.156', first_port=20, last_port=26, portscan_variable=portscan)
        self.assertEqual(portscan["filtered_or_open_ports"], [20, 21, 22, 23, 24, 25])

    def test_writeToXML(self):
        """The function should write the port scan results to a XML file."""
        portscan_variable = {"host": "45.33.32.156",
                             "scan_type": "-sS",
                             "open_ports": [22],
                             "closed_ports": [20, 21, 23, 24, 25],
                             "filtered_ports": [],
                             "filtered_or_open_ports": [],
                             "filtered_or_closed_ports": []}
        XML.writeToXML(portscan_variable)
        exists_file = os.path.isfile('portscan.xml')
        self.assertIs(exists_file, True)

    def test_writeToSQLite(self):
        """The function should write the port scan results to a SQLite database file."""
        portscan_variable = {"host": "45.33.32.156",
                             "scan_type": "-sS",
                             "open_ports": [22],
                             "closed_ports": [20, 21, 23, 24, 25],
                             "filtered_ports": [],
                             "filtered_or_open_ports": [],
                             "filtered_or_closed_ports": []}
        SQL.writeToSQLite(portscan_variable)
        exists_file = os.path.isfile('portscan.db')
        self.assertIs(exists_file, True)

    def tearDown(self):
        """Tear down all created files."""
        file_list = ["portscan.db", "portscan.xml", "portscan.json"]
        for file in file_list:
            if os.path.isfile(file):
                os.remove(file)

if __name__ == "__main__":
    unittest.main()