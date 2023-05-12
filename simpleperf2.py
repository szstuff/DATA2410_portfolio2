import header
import socket
import argparse
import sys
import re
import time
import os
from header import *


# Main server function, initialises the server with specified parameters
def server(ip, port, reliability, testcase, window_size):
    # ip and port: Which IP-address and port the server should listen to
    # reliability: What reliability protocol should be used for the connection
    # testcase: XXXXX ????

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # creating the socket
    # This code runs through ports until it finds an open one
    firstPort = port  # Used to quit the program when server can't bind to a provided IP and every port from 1024-65534.
    while True:  # Loops through all ports for the given IP and binds to the first available one.
        try:  # Used to handle exceptions when server can't bind to a port without quitting the program.
            server_socket.bind((ip, port))  # Attempts to bind with provided IP and current port
            break  # Break out of loop if bind didn't raise an exception
        except OSError:  # Catches exceptions when binding
            port = port + 1  # Iterates port for the next bind attempt
        if port == 65535:
            port = 1024  # Used to run through remaining ports in the valid range.
        elif (port == firstPort - 1):  # If the current port is the one prior to the first port, an error message
            # is shown. It's worth noting that the last port can't be tested because of this
            raise Exception("Could not bind to any port on IP " + str(ip))

    print("##### Server is up and listening on " + str(ip) + ":" + str(port))

    #######
    # Threeway handshake for initialising connection
    #######
    print("##### Waiting for threeway handshake")
    # 1. Receive and parse SYN from client
    data, client_address = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(data)  # Extract information from received packet
    if not flags == 8:  # If packet is not a SYN packet
        raise Exception("Expected SYN (8) packet. Received: " + str(flags))

    # 2. Send SYN-ACK packet to client
    sequence_number = 0
    acknowledgment_number = seq  # Server acknowledges that packet with sequence_nr is received
    flags = 12  # SYN-ACK flags

    # Create packet with header fields
    packet = create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
    server_socket.sendto(packet, client_address)  # Send packet to client

    # 3. Receive final ACK from client
    data, client_address = server_socket.recvfrom(1472)  # Wait for packet to arrive
    seq, ack, flags, win = parse_header(data)  # Extract header fields from received packet

    if not flags == 4:  # If packet is not an ACK packet
        raise Exception("Expected SYN (8) packet. Received: " + str(flags))

    # Preparing for file transfer
    filename = ""
    no_of_packets = 0
    expectedFilesize = 0
    received_data = []

    ########
    # Receive metadata from client
    ########
    print("##### Preparing to receive metadata")
    while True:
        try:
            metadata, client_address = server_socket.recvfrom(1472)  # Wait for packet to arrive
            filename, no_of_packets, expectedFilesize = unpack_metadata(
                metadata)  # Extract metadata from received packet
            no_of_packets = int(no_of_packets)  # Convert no_of_packets into int
            expectedFilesize = int(expectedFilesize)  # Convert expectedFilesize into int
            sequence_number = 0
            acknowledgment_number = 0
            received_data = [None] * (no_of_packets)

            response = create_packet(0, 0, 4, window_size, "".encode())  # Create ACK packet
            server_socket.sendto(response, client_address)  # Send ACK packet
            break
        except Exception as e:
            raise Exception("Exception when receiving metadata" + str(e))
            sys.exit()

    def gbn():
        testcaseNotRun = True
        seqNumTracker = 0

        # Loop through every packet that is received
        # for i in range(no_of_packets):
        while seqNumTracker < no_of_packets:
            try:
                # Receive packet
                packet, client_address = server_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]

                # Add the data to the file at its correct index
                received_data[seq] = data

                if not seqNumTracker == seq:
                    seqNumTracker = seq

                if seqNumTracker == 3 and testcaseNotRun and testcase == "SKIP_ACK":
                    testcaseNotRun = False
                    seqNumTracker += 1
                    continue

                response = create_packet(seq, seq, 4, window_size, "".encode())
                server_socket.sendto(response, client_address)
                seqNumTracker += 1

            except Exception as e:
                print(f"Exception occurred: {e}")

    def sr():
        testcaseNotRun = True
        seqNumTracker = 0

        # Loop through every packet that is received
        # for i in range(no_of_packets):
        while seqNumTracker < no_of_packets:
            try:
                # Receive packet
                packet, client_address = server_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]

                # Add the data to the file at its correct index
                received_data[seq] = data

                if not seqNumTracker == seq:
                    seqNumTracker = seq

                if seqNumTracker == 3 and testcaseNotRun and testcase == "SKIP_ACK":
                    testcaseNotRun = False
                    seqNumTracker += 1
                    continue

                response = create_packet(seq, seq, 4, window_size, "".encode())
                server_socket.sendto(response, client_address)
                seqNumTracker += 1
            except Exception as e:
                print(f"Exception occurred: {e}")

    def stop_wait():
        testcaseNotRun = True
        # Iterate through every expected packet
        i = 0
        # for i in range(no_of_packets):
        while i < no_of_packets:
            try:
                packet, client_address = server_socket.recvfrom(1472)  # Receive a packet
                seq, ack, flags, win = parse_header(packet)  # Parse the header of the packet
                data = packet[12:]  # Extract the data from the packet
                received_data[seq] = data  # Add the received data to the received_data list

                if not i == seq:
                    i = seq

                if seq == i:  # If the received sequence number matches the expected sequence number
                    if i == 3 and testcaseNotRun and testcase == "SKIP_ACK":
                        testcaseNotRun = False
                        i += 1
                        continue
                response = create_packet(seq, seq, 4, window_size, "".encode())  # Create an ACK packet
                server_socket.sendto(response, client_address)  # Send the ACK packet to client
                i += 1
            except Exception as e:  # Handle possible exceptions
                print(f"Exception occurred: {e}")

    if reliability == "SAW":
        print("##### Starting file transfer using Stop and Wait protocol")
        stop_wait()  # Send packet using Stop-And-Wait
    elif reliability == "GBN":
        print("##### Starting file transfer using Go-Back-N protocol")
        gbn()  # Send packet using Go-Back-N protocol
    elif reliability == "SR":
        print("##### Starting file transfer using Selective Repeat protocol")
        sr()  # Send packet using Selective-Repeat

    finalFile = b''  # Empty bytes object to hold joined file data
    # Iterate through received_data array and add packets to finalFile
    print("##### Saving file to disk")

    for i, arrayItem in enumerate(received_data):
        try:
            finalFile += arrayItem
        except Exception as e:
            print("Could not add file with index " + str(i) + " to working file. e: " + str(e))

    # Remove any null bytes in the filename
    filename = filename.replace('\0', '')
    filename = "received_" + str(filename)
    # Save the concatenated file to disk
    f = open((f'received_{str(filename)}'), "wb")
    f.write(finalFile)
    f.close()

    # Clear last line and print completion message.
    print("##### Successfully saved file as " + str(filename))

    # close server
    # A two-way handshake to close the connection
    # sends an ACK to acknowledge the SYN ACK from the client
    # ----------- two way handshake ---------------
    # Receive response and parse header from client
    data, null = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(data)

    if flags == 2:  # If FIN packet received
        # Sends a ACK for the FIN
        sequence_number = 0
        acknowledgment_number = seq  # Server acknowledges that packet with sequence_nr is received
        flags = 6  # FIN-ACK flags

        packet = create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
        server_socket.sendto(packet, client_address)
        server_socket.close()
        print("##### Connection closed")
    else:
        print("Error closing connection")
    # ------- slutten på two way handshake -----------


# Main client function, initialises the client with specified parameters
def client(ip, port, filename, reliability, testcase, window_size):
    # ip and port: Which IP-address and port the client should send to
    # filename: path to file to be sent over the program
    # reliability: What reliability protocol should be used for the connection
    # testcase: Used to simulate issues like lost packets to

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Creating socket
    serverAddress = (ip, port)  # The IP:PORT tuple is saved as a variable for simplicity

    #######
    # Threeway handshake for initialising connection
    # The handshake is also used for calculating the RTT and setting the timeout accordingly
    #######
    # 1. Send SYN to server
    print("##### Threeway handshake")
    sequence_number = 1  # Sequence number for packets sent from client
    acknowledgment_number = 0  # ACK number for packets sent from client
    flags = 8  # SYN flag

    # Create SYN packet
    packet = header.create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
    start_time = time.time()
    client_socket.sendto(packet, serverAddress)

    # 2. Receive and parse SYN-ACK from server
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)
    if flags == 12:  # If flags == SYN+ACK
        end_time = time.time()

        # 3. Client sends final ACK to server
        packet = header.create_packet(sequence_number, ack, 4, window_size, "".encode())
        client_socket.sendto(packet, serverAddress)
    else:
        raise exception('SYN-ACK packet not received!')

    #######
    # Set timeout using measured RTT
    #######
    timeout_s = end_time - start_time
    client_socket.settimeout(4 * timeout_s)
    print("##### Timeout set to " + str(round((4 * timeout_s*1000), 2)) + "ms. RTT: " + str(round((timeout_s*1000), 2)) + "ms.")

    #######
    # Read and prepare the file for transfer
    #######
    # Initialising variables
    file_data = None
    file_size = 0
    packetsize = 1460  # Size of each packet's payload.
    no_of_packets = 0
    split_file = []

    ########
    # Receive metadata from client
    ########
    print("##### Preparing to send metadata")
    # Open file in binary mode and read data
    with open(filename, "rb") as file:
        file_data = file.read()  # Read the contents of the file into a byte string
        file_size = len(file_data)  # Determine size in bytes of the file
        # no_of_packets = int(math.ceil(file_size / packetsize))  # Calculate number of packets this file needs to be split into.

        # Split file into an array where each index contains up to packetsize (1460) bytes
        for index in range(0, file_size, packetsize):
            split_file.append(file_data[index:index + packetsize])

        no_of_packets = len(split_file)

        #######
        # Create metadata containing the filename, total number of packets and the total file size
        #######
        metadata = pack_metadata(filename, no_of_packets, file_size)
        packet = create_packet(1, 0, 0, window_size, metadata)

        while True:
            try:
                # Send the packet to the server
                client_socket.sendto(packet, serverAddress)

                # Wait for a response from the server
                response, null = client_socket.recvfrom(1472)

                # Parse the response header for ACK and flags
                seq, ack, flags, win = parse_header(response)
                if flags == 4 and ack == 0:  # If the response is an ACK == 0, break the loop
                    break
            except Exception as e:
                print("Exception when sending metadata: " + str(e))
                sys.exit()

    def stop_wait():
        offset = sequence_number  # Sequence_number is not 0 because of previous messages.
        # Sequence_number is used as an offset for i to send the correct seq to server

        for i, packet_data in enumerate(split_file):
            # packet = create_packet(i+offset, ack, flags, win, packet_data)
            packet = create_packet(i, 0, 0, window_size, packet_data)

            # Send packet and wait for ACK
            retries = 0
            while retries <= 2 * no_of_packets:  # Dynamically scales allowed amount of retries based on filesize
                try:
                    # Send packet to receiver
                    client_socket.sendto(packet, serverAddress)

                    # Receive ACK
                    response, null = client_socket.recvfrom(1472)
                    seq, ack, flags, win = parse_header(response)
                    # Check if received ACK is for the expected sequence number
                    # if flags == 4 and ack == i+offset: #If flags = ACK and ack is equal to seq
                    if flags == 4 and ack == i:  # If flags = ACK and ack is equal to seq
                        break
                    # elif flags == 4 and ack == i+offset-1:
                    elif flags == 4 and ack == i - 1:
                        continue

                except socket.timeout:
                    retries += 1
                    print(f"Timeout for packet with sequence number: {i}, resending")
                    # Timeout occurred, re-send packet
                    continue

    # Go-Back-N is a protocol that let us send continuous streams of packets without waiting
    # for ACK of the previous packet.
    ###NY VERSJON
    def gbn(serverAddress):
        testcaseNotRun = True

        # Dette er bare for at dere skjønner men base er basically i = 0 som var i SR
        base = 0  # Tracks the oldest sequence number of the oldest unacknowledged packet
        received_acks = [False] * no_of_packets  # List of packets that have not been acknowledged

        while base < no_of_packets - 1:
            for i, ack in enumerate(received_acks):
                if ack and i > base:
                    base = i
                elif ack == False and i > base:
                    break
            scope = base + window_size - 1
            if scope >= no_of_packets:
                scope = no_of_packets - 1
            j = base

            while j <= scope:
                if j == 3 and testcaseNotRun:
                    if testcase == "SKIP_SEQ":
                        j += 1
                        testcaseNotRun = False
                    elif testcase == "DUPLICATE":
                        j -= 1
                        testcaseNotRun = False

                if not received_acks[j]:
                    data = split_file[j]
                    try:
                        received_acks[j + 1] = False
                    except:
                        pass
                    packet = create_packet(j, 0, 0, window_size, data)

                    # Send packet to receiver
                    client_socket.sendto(packet, serverAddress)

                j += 1

            try:
                # Receive ACK
                j = base
                while j <= scope:
                    response, null = client_socket.recvfrom(1472)
                    seq, ack, flags, win = parse_header(response)

                    if flags == 4:  # If flags = ACK and ack is equal to seq
                        received_acks[ack] = True

                        if base == no_of_packets:
                            break
            except socket.timeout:
                print("Timeout occurred. Resending packets...")
                # Vi må finne en måtte å håndtere timeout

    def sr():
        testcaseNotRun = True
        # Jeg kopierte jovia sin GBN for å prøve å fikse feilen uten å slette fremgang <3

        # Dette er bare for at dere skjønner men base er basically i = 0 som var i SR
        base = 0  # Tracks the oldest sequence number of the oldest unacknowledged packet
        received_acks = [False] * no_of_packets  # List of packets that have not been acknowledged

        while base < no_of_packets - 1:
            for i, ack in enumerate(received_acks):
                if ack and i > base:
                    base = i
                elif ack == False and i > base:
                    break
            scope = base + window_size - 1
            if scope >= no_of_packets:
                scope = no_of_packets - 1
            j = base

            while j <= scope:
                if j == 3 and testcaseNotRun:
                    if testcase == "SKIP_SEQ":
                        j += 1
                        testcaseNotRun = False
                    elif testcase == "DUPLICATE":
                        j -= 1
                        testcaseNotRun = False

                if not received_acks[j]:
                    data = split_file[j]
                    packet = create_packet(j, 0, 0, window_size, data)

                    # Send packet to receiver
                    client_socket.sendto(packet, serverAddress)

                j += 1

            try:
                # Receive ACK
                j = base
                while j <= scope:
                    response, null = client_socket.recvfrom(1472)
                    seq, ack, flags, win = parse_header(response)

                    if flags == 4:  # If flags = ACK and ack is equal to seq
                        received_acks[ack] = True

                        if base == no_of_packets:
                            break
                    else:
                        pass
            except socket.timeout:
                print("Timeout occurred. Resending packets...")
                # Vi må finne en måtte å håndtere timeout

    # Sender sends a packet and waits to receive ack. After receiving ack, a new packet will be sendt.
    # If no ack received, it waits for timeout, and tries to send the packet again.

    # SR: Du får ack etter hver eneste pakke.

    # Send file with chosen reliability protocol
    transferStartTime = time.time()
    if reliability == "SAW":
        stop_wait()  # Send packet using Stop-And-Wait
    elif reliability == "GBN":
        gbn(serverAddress)  # Send packet using Go-Back-N protocol
    elif reliability == "SR":
        sr()  # Send packet using Selective Repeat protocol
    transferEndTime = time.time()
    transferTime = transferEndTime - transferStartTime

    file.close()

    # Clear last line and print completion message.
    print("##### Transfer complete.")
    print("## Total time: " + str(round(transferTime, 2)) + ". Size of file transferred: " + str(
        file_size / 1000) + "KB.")
    file_size = file_size * 8  ## Converting file_size to bits
    throughput = (file_size / transferTime) / 1000_000  ##Calculating Mbps
    print("## Throughput: " + str(round(throughput, 2)) + "Mbps")

    # ------- two way handshake ---------
    # ends the connection with a two-way handshake
    # Create FIN packet and sends to server
    sequence_number = 0
    acknowledgment_number = seq  # Server acknowledges that packet with sequence_nr is received
    flags = 2  # FIN flags

    packet = header.create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
    client_socket.sendto(packet, serverAddress)

    # Receive response and parse header
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)

    # Recives ACK for the FIN and closes connection
    if flags == 6:  # If flags == ACK
        client_socket.close()
        print("##### Connection closed")

    else:
        print("Error closing connection from client")

    # ----- slutten på two way handshake -------


# Packs file metadata. Used in client to tell server how to name the file and how big it is
def pack_metadata(filename, no_of_packets, filesize):
    return (str(filename) + ":" + str(no_of_packets) + ":" + str(filesize)).encode()


# Unpacks metadata. Used by server to check for errors (comparing expected and actual filesize), name file and how many packets to expect
def unpack_metadata(metadata):
    metadata = metadata.decode()
    array = metadata.split(":")
    filename = array[0]
    no_of_packets = array[1]
    filesize = array[2]
    return filename, no_of_packets, filesize


# Check-metoder
###

def checkFile(filename):  # Checks if the file exists in the server's system
    if filename == None:
        return None
    if os.path.isfile(filename):
        return filename
    else:
        raise argparse.ArgumentTypeError("Could not find file with path " + str(filename))


def checkIP(val):  # Checks input of -i flag
    if val == "localhost":  # Used to skip regex, as "localhost" does not match the pattern of an IPv4 address
        return "localhost"
    ipcheck = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", str(val))  # regex for IPv4 address
    ipOK = bool(ipcheck)
    if ipOK:
        splitIP = val.split(".")  # Splits IP at decimal point
        for byte in splitIP:  # For every octet, check if it's in the valid range og 0-255
            if int(byte) < 0 or int(byte) > 255:
                raise argparse.ArgumentTypeError(str(val) + "is not a valid IPv4 address")
    return val  # Return user specified IP if all checks pass


def checkPort(val):  # Checks input of -p port flag
    try:
        value = int(val)  # Port must be an integer
    except ValueError:
        raise argparse.ArgumentTypeError("Expected an integer but you entered a string")
    if value < 1024 or value > 65535:  # Port must be in valid range
        raise argparse.ArgumentTypeError(str(value) + " is not a valid port")
    return value


# Check reliability type from command line argument
def checkReliability(val):
    val = val.upper()
    if val is None:
        return None
    elif val == "SAW" or val == "STOP_AND_WAIT":
        return "SAW"
    elif val == "GBN":
        return "GBN"
    elif val == "SR":
        return "SR"
    else:
        raise Exception(
            "Could not parse -r reliability input. Expected: \"SAW\", \"STOP_AND_WAIT\", \"GBN\" or \"SR\". Actual: " + str(
                val))


# Check test case type from command line argument
def checkTestCase(val):
    val = val.upper()
    if val is None:
        return None
    elif val == "SKIP_ACK" or val == "SKIPACK" or val == "LOSS":
        return "SKIP_ACK"
    elif val == "SKIP_SEQ" or val == "SKIPSEQ" or val == "REORDER":
        return "SKIP_SEQ"
    elif val == "DUP" or val == "DUPLICATE":
        return "DUPLICATE"
    else:
        raise Exception(
            "Could not parse -t testcase input. Expected: \"SKIP_ACK\", \"SKIP_SEQ\" or \"LOSS\", Actual: " + str(val))


# Window size from command line argument
def checkWindow(val):
    val = int(val)
    if not (1 <= val <= 15):
        raise Exception("Invalid window_size. Expected value between 1 and 15. Actual: " + str(val))
    else:
        return val


parser = argparse.ArgumentParser(description="positional arguments",
                                 epilog="end of help")  # Initialises argsparse parser
# Arguments
parser.add_argument('-s', '--server', action='store_true', default=False, help="Start in server mode. Default.")
parser.add_argument('-c', '--client', action='store_true', default=False, help="Start in client mode")
parser.add_argument('-i', '--ip', type=checkIP, default="127.0.0.1", help="Server IP")
parser.add_argument('-p', '--port', type=checkPort, default="8088", help="Bind to provided port. Default 8088")
parser.add_argument('-f', '--file', type=checkFile, default=None, help="Path to file to transfer")
parser.add_argument('-r', '--reliable', type=checkReliability, default="SAW",
                    help="Choose method for transfer (SAW, GBN or SR)")
parser.add_argument('-t', '--testcase', type=checkTestCase, default=None,
                    help="Simulate loss of packets to test error handling in the code.")
parser.add_argument('-w', '--windowsize', type=checkWindow, default=5, help="Set the window size for GBN and SR.")
args = parser.parse_args()  # Parses arguments provided by user

if args.server:
    print("##### Starting in server mode")
    print("## Protocol: " + str(args.reliable) + " | Testcase: " + str(args.testcase) + " | Window: " + str(
        args.windowsize))
    server(args.ip, args.port, args.reliable, args.testcase, args.windowsize)
elif args.client:
    print("##### Starting in client mode")
    print("## Protocol: " + str(args.reliable) + " | File: " + str(args.file) + " | Testcase: " + str(
        args.testcase) + " | Window: " + str(args.windowsize))
    client(args.ip, args.port, args.file, args.reliable, args.testcase, args.windowsize)
else:
    print("##### Could not start the program.")

'''
NOTTATER til LAB
1. RTT. Det settes i topologifilen (felt delay)
2. Testcase. Det holder å hardkode i 1 skip/1 loss i hver 
3. Hvilke testcases skal det være? Hva skal de gjøre?
4. 

HUSK Å FIKSE FØLGENDE FØR INNLEVERING <3:
1. Når SR kjøres med stor testfil og testcase SKIPACK, det står feilmelding på klient:
    Error closing connection from client
2. Vi har retry i SAW. Enten legg det til alle klienter, eller slett det fra SAW 
'''
