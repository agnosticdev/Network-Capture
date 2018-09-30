# Network Capture
Python wrapper around tcpdump for fine grain search criteria that is written the final pcap.

Network Capture was built as a Python around TCPDUMP to provide more advanced packet filtering.  Currently there is complexity and user confusion around the usage of filters and arguments while using TCPDUMP.  This module attempts to normalize that problems by giving the user very straight forward usage filter keywords and criteria. 

For example, when filtering on either the port, ip, or the interface you can specify the keywords that you are looking for in your traffic dump to be captured and written to the final output file.

```bash
$ cpython/cpython network_capture.py -ip 199.99.99.99 -k error,host,ssl
$ cpython/cpython network_capture.py -port 80 -k error,host,ssl
$ cpython/cpython network_capture.py -interface enp4s0 -k error,host,ssl
```
