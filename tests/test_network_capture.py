# -*- coding: utf-8 -*-
#
# Network_Capture Module has been built as a standalone module 
# This file is to test the functionality of Network_Capture.
#
# Executet the test file:
# python -m unittest
#
#

import os, sys, unittest
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

	def test_no_arguments(self):
		try:
			nc = network_capture([])
			self.fail("Program did not exit.  Failure.")
		except SystemExit:
			self.assertTrue(True)


if __name__ == "__main__":
	unittest.main()