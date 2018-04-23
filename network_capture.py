# -*- coding: utf-8 -*-
#
# Network_Capture Module has been built as a standalone module 
#
# Note: At the time of writing this script, it is intended for unix systems.
# Windows currently is not supported.
#
#
# Note if you are running this module in Linux you may need to alter app armor.
# Specifically in Ubuntu aa-complain needed to be setup instead of aa-enforce
# $ sudo aa-complain /usr/sbin/tcpdump
# $ sudo aa-enforce /usr/sbin/tcpdump
#
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

			self.capture_cmd = "sudo tcpdump host " + self.ip + " -vv"
		elif "-port" == args[0][1] and args[0][2] is not None:
			self.port = args[0][2]
			if not self.validate_port(self.port):
				exit("The port being used is not valid.")

			self.capture_cmd = "sudo tcpdump port " + self.port + " -vv"
		elif "-interface" == args[0][1] and args[0][2] is not None:
			self.interface = args[0][2]
			if not self.validate_interface(self.interface):
				exit("The interface being used is not up.")

			self.capture_cmd = "sudo tcpdump -i " + self.interface + " -vv"

		if "-k" == args[0][3] and args[0][4] is not None:
			self.keywords = args[0][4].split(",")

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
		unix_socket.close()
		if flags & 1:
			return True
		else:
			return False


	def get_filename(self):
		return f"network_capture_{datetime.datetime.now():%Y-%m-%d-%m:%s}.txt"


	def capture(self):

		print("Capturing command: {0}".format(self.capture_cmd))
		line_count = 0
		captue_process = None
		capture_stdout = None

		try:
			capture_file_object = open(self.filename, "w")
		except IOError as err:
			print("-- Exiting due to an IOError --")
			print("Error: {0}".format(err))
			sys.exit(0)
		
		try:
			# Just to make sure you do not need to enter your password.
			# Set the mode for the file to full read/write
			os.system("chmod 777 " + self.filename)

			# Start the capture
			captue_process = subprocess.Popen([self.capture_cmd], 
											  shell=True,
											  stdout=subprocess.PIPE)

			print("-- Start Capturing Network Traffic --")

			while True:
				captured_line = captue_process.stdout.readline()
				if captured_line is not None and captured_line != b'':
					captured_line = captured_line.decode("utf-8")
					print("{0} \n".format(captured_line))
					# Check for the keywords in the list 
					if any(key in captured_line for key in self.keywords):
						print("** Keyword found. Writing to log **")
						capture_file_object.write(captured_line + "\n")
						line_count += 1

		except OSError as err:
			capture_file_object.close()
			captue_process.kill()
			captue_process.wait()
			print("-- Exiting due to an operating system failure --")
			print("-- {0} lines captured in your filter --".format(line_count))
			print("Error: {0}".format(err))
			sys.exit(0)
		except KeyboardInterrupt:
			capture_file_object.close()
			captue_process.kill()
			captue_process.wait()
			print("-- Exiting due to keyboard interrupt --")
			print("-- {0} lines captured in your filter --".format(line_count))
			sys.exit(0)
		except:
			capture_file_object.close()
			captue_process.kill()
			captue_process.wait()
			print("-- Unexpected excpetion received --")
			print("-- {0} lines captured in your filter --".format(line_count))
			print("Errors: {0}".format(sys.exc_info()[0]))
			sys.exit(0)




nc = network_capture(sys.argv)
nc.capture()

