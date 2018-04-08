# Network-Capture
Python wrapper around tcpdump for fine grain search criteria that is written the final log file.

For example, when filtering on eith the port, ip, or the interface you can specify the keywords you are looking for in your traffic dump to be captured and written to the final output file.

```bash
$ cpython/cpython network_capture.py -ip 199.99.99.99 -k error,host,ssl
$ cpython/cpython network_capture.py -port 80 -k error,host,ssl
$ cpython/cpython network_capture.py -interface enp4s0 -k error,host,ssl
```
