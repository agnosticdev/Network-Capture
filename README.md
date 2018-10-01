# Network Capture
Python wrapper around tcpdump for fine grain search criteria that is written the final pcap.

Network Capture was built as a Python wrapper around TCPDUMP to provide more advanced packet filtering in the output of your pcap or txt files.  Currently there is complexity on filtering the right information while using TCPDUMP, and this module attempts to normalize these problems by giving the user an open set of keywords and criteria to generate file based upon. 

For example, when filtering on either the port, ip, or the interface you can specify the keywords that you are looking for in your traffic dump to be captured and written to the final output file. The final output will be a pcap and a txt file for review.

```bash
# Host (199.99.99.99) capture for keys: error,host,ssl
$ python network_capture.py host 199.99.99.99 -keys error,host,ssl

# Port (80) capture  for keys: error,host,ssl
$ python network_capture.py port 80 -keys error,host,ssl

# Port (80) capture  for keys: error,host,ssl
$ python network_capture.py -i en0 -keys error,host,ssl

```

## Note
This module does not attempt to rebuild the functionality currently found in TCPDUMP, but rather to utilize it to make filtering stronger.

There are some built in validation routines available in this module that can validate common arguments like port number, host, and interface, but these are just extra utilities that attempt to add extra benefit on top of TCPDUMP. 