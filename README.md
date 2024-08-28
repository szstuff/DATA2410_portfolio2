created for an exam for course DATA2410 at OsloMet by:
	STILIAN TODOROV ZAGOROV – S364531
	NGOC LINN VU HUYNH – S364523
	SALONI ARORA CHITKARA – S364538
	JOVIA NAMAYANJA KAGGWA – S364526

The application is a file transfer utility created in Python that uses UDP with custom-made error-handling code to transfer files over the network. The program transfers data reliably and can handle issues related to packets received out of order, duplicate packets, and missing packets.  

Reliability is ensured by using one of three supported reliable transfer methods based on ARQ: Stop-and-Wait, Go-Back-N, and Selective-Repeat. 

The application supports artificial test cases that trigger on the 3rd packet of the transfer. Supported test cases are SKIP_ACK (Simulate loss of acknowledgement), SKIP_SEQ (Simulate loss of packet and reordering) and DUPLICATE (Simulate duplicate transmission)

**Installation and prerequisites:**
No installation required
Python3 required

**Usage:**
The application can be run with the following arguments:

**Server:**
python3 application.py -s -i <ip_address> -p <port> -r <reliable> -w <window_size> -t <testcase>

-s: Starts the application in server mode 

-i <ip_address>: IP address the server should connect to. Default: 127.0.0.1

-p <port>: Port that the server should use. Default: 8088 (1024-65534)

-r <reliable>: Which reliability protocol to use for the transfer. Supported: SAW, GBN, SR.

-w <window_size>: How many packets to send at a time (only GBN and SR). (1-15)

-t <testcase>: Which test case to use when receiving data. Supported: SKIP_ACK

**Client:**
python3 application.py -c -i <ip_address> -p <port> -f [path_to_file] -r <reliable> -w <window_size> -t <testcase> 

-s: Starts the application in client mode

-i <ip_address>: IP address the server should connect to. Default: 127.0.0.1

-p <port>: Port that the server should use. Default: 8088 (1024-65534)

-f [path_to_file]: Specify the path to the file to transfer. 

-r <reliable>: Which reliability protocol to use for the transfer. Supported: SAW, GBN, SR.

-w <window_size>: How many packets to send at a time (only GBN and SR). (1-15)

-t <testcase>: Which test case to use when receiving data. Supported: SKIP_SEQ, DUPLICATE

**Output:**
The output from the application is printed in the terminal. The client prints information like the measured RTT, transfer time and measured throughput. The client and server both print configuration info including the protocol, file, testcase and window size used for the transfer.
