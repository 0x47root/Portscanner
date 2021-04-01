import unittest
from main import *
from portscans import *
from XML import *
from SQL import *

class MainTests(unittest.TestCase):

    # def setUp(self):
    #     # Do setup here.
    #     pass

    # def test_create_banner(self):
    #     """The function should create a banner."""
    #     self.assertIsNotNone(create_banner())

    # def test_ask_scantype(self):
    #     """The function should ask the user for input and output -sT, -sU, -sS or -sX."""
    #     self.assertIn(ask_scantype(), ['-sT', '-sU', '-sS', '-sX'])

    # def test_ask_host(self):
    #     """The function should ask the user for input and return a string."""
    #     self.assertIsInstance(ask_host(), str)

    def test_ask_first_port(self):
        """The function should ask the user for input and output an integer between 1 and 65535."""
        self.assertIn(ask_first_port(), range(1, 65536))

    # def tearDown(self):
    #     # Do teardown here.
    #     pass

if __name__ == "__main__":
    unittest.main()