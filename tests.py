import unittest
from main import *
from portscans import *
from XML import *
from SQL import *

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
        Finally the function should output 'JSON', 'XML', 'json' or 'xml'.
        """
        self.assertIn(ask_output(), ['JSON', 'XML', 'json', 'xml'])

    def test_create_dict(self):
        """
        The function should create a dictionary to store the scan results in.
        """
        self.assertIsInstance(create_dict(target='45.33.32.156', scan_type='-sS'), dict)

    def test_TCP_connect_scan(self):
        """
        The function should conduct a TCP-Connect scan to a specific IP address and write the results to
        the dictionary with the name 'portscan'. While testing, the port range 20-25 is used on 'scanme.nmap.org'.
        Port 22 should be open and the other ports should be filtered ot closed.
        """
        portscan = create_dict(target='45.33.32.156', scan_type='-sT')
        TCP_connect_scan(target='45.33.32.156', first_port=20, last_port=25, portscan_variable=portscan)
        self.assertEqual(portscan["filtered_or_closed_ports"], [20, 21, 23, 24])
        self.assertEqual(portscan["open_ports"], [22])

if __name__ == "__main__":
    unittest.main()