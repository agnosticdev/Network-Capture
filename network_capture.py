# -*- coding: utf-8 -*-
#
# Network_Capture Module has been built as a standalone module 
#
# Note: At the time of writing this script, it is intended for unix systems.
# Windows currently is not supported.
#

import os, sys, datetime, platform, ipaddress, fcntl, struct
from socket import *

# cpython/cpython network_capture.py -ip 199.99.99.99 -k error,host,ssl
# cpython/cpython network_capture.py -port 80 -k error,host,ssl
# cpython/cpython network_capture.py -interface enp4s0 -k error,host,ssl


class network_capture(object):

	__slots__ = ('ip', 'port', 'interface', 
				 'keywords', 'traffic_command', 'filename')

	def __init__(self, *args):

		self.keywords = []
		self.filename = self.get_filename()

		# Make sure and validate the platform and the presence of tcpdump.
		if not self.validate_platform()
			exit("Make sure you are on a unix system with tcpdump installed.")

		if "-ip" in args and args[3] is not None:
			self.ip = args[3]
			if not self.validate_ip(self.ip):
				exit("The ip being used is not valid.")

			self.traffic_command = "tcpdump host " + self.ip + " -w " \
									+ self.filename
		elif "-port" in args and args[3] is not None:
			self.port = args[3]
			if not self.validate_port(self.port):
				exit("The port being used is not valid.")

			self.traffic_command = "tcpdump port " + self.port + " -w " \
									+ self.filename
		elif "-interface" in args and args[3] is not None:
			self.interface = args[3]
			if not self.validate_interface(self.interface):
				exit("The interface being used is not up.")

			self.traffic_command = "tcpdump -i " + self.port + " -w " \
									+ self.filename

		if "-k" in args and args[5] is not None:
			self.keywords = args[5].split(",")


		# Finally perform the capture


	def validate_platform(self):
		# This is only for unix system
		if platform.system() is "Windows":
			print("network_traffic is not supportd by Windows.")
			return False

		if os.system("tcpdump") is not 0:
			print("There was an issue detecting tcpdump.")
			return False

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
		return f"network_cpature_{datetime.datetime.now():%Y-%m-%d-%m:%s}.txt"


	def capture(self):
		print("Capturing!")


nc = network_capture(sys.argv)
nc.capture()

