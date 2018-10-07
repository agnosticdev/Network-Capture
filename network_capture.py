# -*- coding: utf-8 -*-
#
# Network_Capture Module has been built as a standalone module 
# Network Capture was built around TCPdump to provide more advanced packet
# filtering.  Currently there is complexity around the usage of filters and
# arguments while using TCPdump.  This module aims to improve that. 
#
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
import asyncio, pickle
from socket import *

# Host (199.99.99.99) capture for keys: error,host,ssl
# $ python network_capture.py host 199.99.99.99 -keys error,host,ssl

# Port (80) capture  for keys: error,host,ssl
# $ python network_capture.py port 80 -keys error,host,ssl

# Port (80) capture  for keys: error,host,ssl
# $ python network_capture.py -i enp4s0 ip6 -keys error,host,ssl

#
# TODO:
#  1) Generate valid TCPdump pcap (Binary stream is not valid right now)
#  2) Add tests
#  
#


class network_capture(object):

	__slots__ = ('keywords', 
				 'capture_cmd', 
				 'txt_file',
				 'pcap_file',
				 'validation_values',
				 'validation_map')

	def __init__(self, *args):

		self.keywords = []
		self.capture_cmd = None
		self.validation_values = {
			'host': '',
			'port': '',
			'-i': ''
		}
		self.validation_map = {
			'host': 'validate_host',
			'port': 'validate_port',
			'-i': 'validate_interface'
		}

		# Set both the filtered pcap and txt file names
		filename = self.get_filename()
		self.txt_file = filename + '.txt'
		self.pcap_file = filename + '.pcap'


		# Set args as an array of arrays
		args = list(args)

		# Make sure the list has usable arguments.
		if len(args[0]) is 1:
			exit("Please provide arguments to execute the program.")

		# Make sure and validate the platform and the presence of tcpdump.
		if not self.validate_platform():
			exit("Make sure you are on a unix system with tcpdump installed.")

		# Build the capture command passed in for TCPdump
		self.capture_cmd = "sudo tcpdump"

		# Iterate through the arguments to get the commands
		for index, val in enumerate(args[0]):
			if index > 0 and args[0][(index - 1)] == "-keys":
				if "," not in val:
					self.keywords.append(val)
				else:
					self.keywords = val.split(",")
			elif index > 0 and val != '-keys':
				self.capture_cmd += " {0}".format(val)
				if val in self.validation_values:
					self.validation_values[val] = args[0][(index + 1)]


		# Set the verbose flags for TCPdump 
		self.capture_cmd += " -vvv -XX"

		# Validation check to make sure we have extracted -keys at this point
		if len(self.keywords) == 0:
			exit("Please make sure you provide keyword, exiting.")


		# Iterate through the collected validation routines
		# Make sure if the validation routines are available, they can be used.
		for key, val in self.validation_values.items():
			if val != '':
				validate_method = getattr(self, self.validation_map[key])
				validate_method(val)


	# Platform validation
	def validate_platform(self):
		# This is only for unix system
		if platform.system() is "Windows":
			print("network_traffic is not supportd by Windows.")
			return False

		# TODO: validate TCPdump is on the machine

		return True

	# Host validation
	def validate_host(self, host):
		try:
			host = ipaddress.ip_address(host)
		except ValueError:
			message = f'Host: {host!r} could not be set to IPv4 or IPv6.'
			print(message)
			exit("The host being used is not valid, exiting.")

	# Port validation
	def validate_port(self, port):
		try:
			port = int(port, 10)
		except ValueError:
			message = f'Port could not be cast to integer value as {port!r}'
			print(message)
			exit("The port being used is not valid, exiting.")
		if not ( 0 <= port <= 65535):
			print("Port out of range 0-65535")
			exit("The port being used is not valid, exiting.")
	
	# Interface validation
	def validate_interface(self, interface):
		print("validate_interface!!!!")
		SIOCGIFFLAGS = 0x8913
		null256 = '\0'*256

		unix_socket = socket(AF_INET, SOCK_DGRAM)
		fd = fcntl.ioctl(unix_socket.fileno(), SIOCGIFFLAGS, interface + null256)
		flags, = struct.unpack('H', fd[16:18])
		unix_socket.close()
		if flags & 1:
			pass
		else:
			exit("The interface being used is not up.")

	# Get a filename to set for both the pcap and txt filtered file
	def get_filename(self):
		return f"network_capture_{datetime.datetime.now():%Y-%m-%d-%m:%s}"

	def capture_error(self):
		print("capture_error")

	async def dispatch_capture(self):

		print("Capturing command: {0}".format(self.capture_cmd))
		print("Capturing keywords: {0}".format(self.keywords))
		line_count = 0
		capture_pid = None
		capture_stdout = None

		# Open a file and start the capture with the files context for read/write
		with open(self.txt_file, 'w') as txt_file_obj, \
			open(self.pcap_file, 'wb') as pcap_file_obj:

			try:
				# Just to make sure you do not need to enter your password.
				# Set the mode for the file to full read/write
				os.system("chmod 777 " + self.txt_file)
				os.system("chmod 777 " + self.pcap_file)

				print("-- Start Capturing Network Traffic --")

				capture_pid = await self.capture_process()
				while True:
					captured_line = await self.capture_read_bytes(capture_pid)

					if captured_line is not None and captured_line != b'':

						captured_line = captured_line.decode("utf-8")
						print("{0} \n".format(captured_line))
						if any(key in captured_line for key in self.keywords):
							print("** Keyword found. Writing to log **")
							txt_file_obj.write(captured_line + "\n")
							# Removing this until this works
							#pickle.dump(captured_line, pcap_file_obj)
							line_count += 1

			except OSError as err:
				print("-- Exiting due to an operating system failure --")
				print("-- {0} lines captured in your filter --".format(line_count))
				print("Error: {0}".format(err))
				sys.exit(0)
			except AttributeError as err:
				print("-- Exiting due to an AttributeError --")
				print("-- {0} lines captured in your filter --".format(line_count))
				print("Error: {0}".format(err))
			except:
				print("-- Unexpected excpetion received --")
				print("-- {0} lines captured in your filter --".format(line_count))
				print("Errors: {0}".format(sys.exc_info()[0]))
				sys.exit(0)
			finally:
				txt_file_obj.close()
				pcap_file_obj.close()
				await self.kill_process(capture_pid)


	async def capture_process(self):
		return await asyncio.create_subprocess_shell(self.capture_cmd, 
												  stdout=asyncio.subprocess.PIPE,
												  stderr=asyncio.subprocess.PIPE)

	async def capture_read_bytes(self, capture_pid):
		return await capture_pid.stdout.readline()

	async def kill_process(self, capture_pid):
		capture_pid.kill()
		await capture_pid.wait()



if __name__ == '__main__':
	# Create a new network capture object and pass in the system arguments
	nc = network_capture(sys.argv)
	# Create a new run loop
	eventloop = asyncio.get_event_loop()
	try:
		# Execute capture until complete.
		eventloop.run_until_complete(nc.dispatch_capture())
	except KeyboardInterrupt as e:
		print("-- Exiting due to keyboard interrupt --")
	finally:
		eventloop.close()