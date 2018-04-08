# -*- coding: utf-8 -*-
#
# Network_Capture Module has been built as a standalone module 
#
# Note: At the time of writing this script, it is intended for unix systems.
# Windows currently is not supported.
#

import os, sys, datetime, platform, ipaddress, fcntl, struct, subprocess
from socket import *

# cpython/cpython network_capture.py -ip 199.99.99.99 -k error,host,ssl
# cpython/cpython network_capture.py -port 80 -k error,host,ssl
# cpython/cpython network_capture.py -interface enp4s0 -k error,host,ssl


class network_capture(object):

	__slots__ = ('ip', 'port', 'interface', 
				 'keywords', 'capture_cmd', 'filename')

	def __init__(self, *args):

		self.keywords = []
		self.filename = self.get_filename()
		self.capture_cmd = None

		args = list(args)

		# Make sure and validate the platform and the presence of tcpdump.
		if not self.validate_platform():
			exit("Make sure you are on a unix system with tcpdump installed.")

		if "-ip" == args[0][1] and args[0][2] is not None:
			self.ip = args[0][2]
			if not self.validate_ip(self.ip):
				exit("The ip being used is not valid.")

			self.capture_cmd = "sudo tcpdump host " + self.ip + " -w " \
									+ self.filename
		elif "-port" == args[0][1] and args[0][2] is not None:
			self.port = args[0][2]
			if not self.validate_port(self.port):
				exit("The port being used is not valid.")

			self.capture_cmd = "sudo tcpdump port " + self.port + " -w " \
									+ self.filename
		elif "-interface" == args[0][1] and args[0][2] is not None:
			self.interface = args[0][2]
			if not self.validate_interface(self.interface):
				exit("The interface being used is not up.")

			self.capture_cmd = "sudo tcpdump -i " + self.port + " -w " \
									+ self.filename

		if "-k" == args[0][3] and args[0][4] is not None:
			self.keywords = args[0][4].split(",")

		print(self.capture_cmd)
		# Perform the capture after all validation is complete
		if self.capture_cmd is not None:
			self.capture()
		else:
			exit("Something went wrong parsing the input.  Capture failed.")


	def validate_platform(self):
		# This is only for unix system
		if platform.system() is "Windows":
			print("network_traffic is not supportd by Windows.")
			return False

		# TODO: validate tcpdump is on the machine

		return True


	def validate_ip(self, ip):
		try:
			ip = ipaddress.ip_address(ip)
		except ValueError:
			message = f'IP: {ip!r} could not be set to IPv4 or IPv6.'
			print(message)
			return False
		return True

	def validate_port(self, port):
		try:
			port = int(port, 10)
		except ValueError:
			message = f'Port could not be cast to integer value as {port!r}'
			print(message)
			return False
		if not ( 0 <= port <= 65535):
			print("Port out of range 0-65535")
			return False
		
		return True

	def validate_interface(self, interface):
		SIOCGIFFLAGS = 0x8913
		null256 = '\0'*256

		unix_socket = socket(AF_INET, SOCK_DGRAM)
		fd = fcntl.ioctl(unix_socket.fileno(), SIOCGIFFLAGS, interface + null256)
		flags, = struct.unpack('H', fd[16:18])
		if flags & 1:
			return True
		else:
			return False


	def get_filename(self):
		return f"network_capture_{datetime.datetime.now():%Y-%m-%d-%m:%s}.txt"


	def capture(self):

		try:
			print(self.capture_cmd)
			# Open a new file for filter capture
			capture_file = open(self.filename, "w")

			# Start the capture
			capture = subprocess.Popen(self.capture_cmd, 
									   shell=True, 
									   stdout=subprocess.PIPE).stdout

			print("-- Start Capturing Network Traffic --")

			while True:
				captured_line = capture.readline()
				if captured_line is not b'':
					print(captured_line)

					# Check for the keywords in the list 
					if any(self.keywords in captured_line for key in self.keywords):
						print("Found keyword, writing to network capture log.")
						capture_file.write(captured_line)

		except OSError as err:
		    print("OS error: {0}".format(err))
		    capture_file.close()
		    capture.terminate()
		    exit("Exiting due to an operating system failure...")
		except KeyboardInterrupt:
			capture_file.close()
			capture.terminate()
			exit("Exiting by directed keyboard interrupt...")
		except:
		    print("Unexpected error:", sys.exc_info()[0])
		    capture_file.close()
		    capture.terminate()
		    exit("Exiting due to an unexpected failure...")




nc = network_capture(sys.argv)
nc.capture()

