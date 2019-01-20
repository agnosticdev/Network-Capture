# Network Capture
Python wrapper around tcpdump for fine grain search criteria that is written to a txt file as well as capturing a pcap.


Network Capture was built as a Python wrapper around TCPdump to provide more advanced  filtering for specific keywords in stdout as well as capturing a pcap file.

Currently there is complexity on filtering the right information while using TCPdump, and this module attempts to normalize these problems by giving the user quick filtering resource by filtering stdout to a text file.

For example, when filtering on either the port, ip, or the interface you can specify the keywords that you are looking for in your traffic dump to be captured and written to a final text file. The final text will contain the filtered search when either error, host, or ssl is found.  If no keywords are passed in then everything from stdout is captured to a txt file.

```bash
# Host (199.99.99.99) capture for keys: error,host,ssl
$ python network_capture.py -host 199.99.99.99 -keys error,host,ssl

# Port (80) capture  for keys: error,host,ssl
$ python network_capture.py -port 80 -keys error,host,ssl

# Port (80) capture  for keys: error,host,ssl
$ python network_capture.py -i en0 -keys error,host,ssl

```

## Note
This module does not attempt to rebuild the functionality currently found in TCPdump, but rather to utilize it to make filtering stronger.

There are some built in validation routines available in this module that can validate common arguments like port number, host, and interface, but these are just extra utilities that attempt to add extra benefit on top of TCPdump. 


## Functionality Road Map

1) Add error handling support.
2) Add enhanced filtering for the pcap from the keys
3) Add formatting support in the module itself.