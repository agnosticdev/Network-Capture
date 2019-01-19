# -*- coding: utf-8 -*-
#
# Network_Capture Module has been built as a standalone module 
# This file is to test the functionality of Network_Capture.
#
# Executet the test file:
# python -m unittest
#
#

import os, sys, unittest, subprocess
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from network_capture import network_capture


class test_network_capture(unittest.TestCase):

	def setUp(self):
		# Setup test data and variables
		self.txt_file = ''
		self.pcap_file = ''

	def tearDown(self):
		# Tear down test data
		self.txt_file = None
		self.pcap_file = None

	def print_message(self, message):
		print(message)

	# Test the case where an exit occurs due to no arguments.
	def test_no_arguments(self):
		try:
			nc = network_capture([])
			self.fail("Program did not exit.  Failure.")
		except SystemExit:
			self.print_message("Success: No args. Caught SystemExit.")
			self.assertTrue(True)
		except:
			self.print_message("Success: No args. Expected error caught.")
			self.assertTrue(True)

	# Test that passing in arguments validates.
	def test_full_arguments(self):
		try:
			args = ['python', 'network_capture.py', 
					'-port', '80', '-keys', 'error,host,ssl']
			nc = network_capture(args)
			self.print_message("Success: Passing full set of args.")
			self.assertTrue(True)
		except SystemExit:
			self.fail("Failure. Caught SystemExit")
		except:
			self.fail("Failure. Caught Exception")

	# Test failing port validation.
	def test_port_validation(self):
		try:
			args = ['python', 'network_capture.py', 
					'-port', '23dsd', '-keys', 'error,host,ssl']
			nc = network_capture(args)
			self.fail("Failure. Port should have failed during validation.")
		except ValueError:
			self.print_message("Success: ValueError on alpha port value.")
			self.assertTrue(True)
		except:
			self.print_message("Success: Exception on alpha port value.")
			self.assertTrue(True)

	# Ensure IPv4 addresses can be validated against a host argument.
	def test_inet_validation(self):
		try:
			args = ['python', 'network_capture.py', 
					'-host', '127.0.0.1', '-keys', 'error,host,ssl']
			nc = network_capture(args)
			self.print_message("Success: Passing inet for host address.")
			self.assertTrue(True)
		except ValueError:
			self.fail("Failure. Caught SystemExit")
		except:
			self.fail("Failure. Caught Exception")

	# Ensure IPv6 addresses can be validated against a host argument.
	def test_inet6_validation(self):
		try:
			args = ['python', 'network_capture.py', 
					'-host', '::1', '-keys', 'error,host,ssl']
			nc = network_capture(args)
			self.print_message("Success: Passing inet6 for host address.")
			self.assertTrue(True)
		except ValueError:
			self.fail("Failure. Caught ValueError")
		except:
			self.fail("Failure. Caught Exception")

	# Ensure that an interface is valid on the machine before the test is run.
	def test_interface_validation(self):
		try:
			interface = 'lo' # Add your interface here
			args = ['python', 'network_capture.py', 
					'-i', interface, '-keys', 'error,host,ssl']
			nc = network_capture(args)
			self.print_message("Success: Passing {0} for interface."
				.format(interface))
			self.assertTrue(True)
		except ValueError:
			self.fail("Failure. Caught ValueError")
		except OSError:
			self.fail("Failure. Caught OSError")
		except:
			self.fail("Failure. Caught Exception")

	# Make sure tcpdump is present on the machine.
	def test_tcpdump_present(self):
		try:
			proc = subprocess.run("tcpdump --version", 
									shell=True, check=True)
			mes = 'Error was not detected, TCPDump must be present.'
			self.print_message("Success: {0}".format(mes))
			self.assertTrue(True)
		except subprocess.CalledProcessError:
			self.fail("Failure. Check that TCPDump is on the system")

if __name__ == "__main__":
	unittest.main()