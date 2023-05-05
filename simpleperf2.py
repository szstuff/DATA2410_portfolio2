from typing import Any
import header
import random
import socket
import threading
import argparse
import sys
import re
import time
import datetime
import struct
import os
from header import *
import math

#Main server function, initialises the server with specified parameters
def server(ip, port, reliability, testcase, window_size):
    #ip and port: Which IP-address and port the server should listen to
    #reliability: What reliability protocol should be used for the connection
    #testcase: XXXXX ????

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     # creating the socket
    # This code runs through ports until it finds an open one
    firstPort = port            # Used to quit the program when server can't bind to a provided IP and every port from 1024-65534.
    while True:                 # Loops through all ports for the given IP and binds to the first available one.
        try:                    # Used to handle exceptions when server can't bind to a port without quitting the program.
            server_socket.bind((ip, port))  # Attempts to bind with provided IP and current port
            break               # Break out of loop if bind didn't raise an exception
        except OSError:         # Catches exceptions when binding
            port = port + 1  # Iterates port for the next bind attempt
        if port == 65535:
            port = 1024  # Used to run through remaining ports in the valid range.
        elif (port == firstPort - 1):  # If the current port is the one prior to the first port, an error message
            # is shown. It's worth noting that the last port can't be tested because of this
            raise Exception("Could not bind to any port on IP " + str(ip))

    print("Server is up and listening on " + str(ip) + ":" + str(port))

    #######
    # Threeway handshake for initialising connection
    #######
    # 1. Receive and parse SYN from client
    data, client_address = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(data)
    if not flags == 8:  # If packet is not a SYN packet
        print(str(flags))
        raise Exception("Expected SYN (8) packet. Received: " + str(flags))

    # 2. Send SYN-ACK packet to client
    sequence_number = 0
    acknowledgment_number = seq     #Server acknowledges that packet with sequence_nr is received
    flags = 12  # SYN-ACK flags
    window = 0
    packet = create_packet(sequence_number, acknowledgment_number, flags, window, "".encode())
    server_socket.sendto(packet, client_address)
    print("Sent SYN-ACK to client")

    # 3. Receive final ACK from client
    data, client_address = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(data)

    if not flags == 4:
        print(str(flags))
        raise Exception("Expected SYN (8) packet. Received: " + str(flags))
    else:
        print("ACK has been received, connection established.")

    # Preparing for file transfer
    filename = ""
    no_of_packets = 0
    expectedFilesize = 0
    received_data = []

    ########
    # Receive metadata from client
    ########
    while True:
        # try:
        metadata, client_address = server_socket.recvfrom(1472)
        filename, no_of_packets, expectedFilesize = unpack_metadata(metadata)
        no_of_packets = int(no_of_packets)
        expectedFilesize = int(expectedFilesize)
        sequence_number = 0
        acknowledgment_number = 0
        received_data = [None] * no_of_packets
        print("Received_data length: " +str(len(received_data)))

        response = create_packet(0, 0, 4, window_size, "".encode())
        server_socket.sendto(response, client_address)
        print("SENT ACK FOR METADATA")
        break
        # except Exception as e:
        #   print("Exception when receiving metadata" + str(e))

    def gbn(filename):
        server_socket.settimeout(0.5)
        expected_seq = 0

        while True:
            # Wait for ACK
            for i in range(window_size):
                try:
                    packet, client_address = server_socket.recvfrom(1472)
                    seq, ack, flags, win = parse_header(packet)
                    data = packet[12:]

                    if flags == 0:
                        if received_data[seq] is None:
                            received_data[seq] = data
                            response = create_packet(0, seq, 4, window_size, "".encode())
                            server_socket.sendto(response, client_address)
                            print(f"Sent ACK {seq}")

                        # If expected_seq packet was received
                        if seq == expected_seq:
                            while received_data[expected_seq] is not None:
                                expected_seq += 1
                except socket.timeout:
                    print("Socket timeout")

                    # Resend packets in current window
                    for packet in range(no_of_packets):
                        seq, ack, flags, win = parse_header(packet)
                        if received_data[seq] is None:
                            server_socket.sendto(packet, client_address)
                            print(f"Resent packet {seq}")
                    break

    def stop_wait():
        for i in range(no_of_packets):
            print("I for " + str(i) + " in no_of_packets: " + str(no_of_packets))
            try:
                packet, client_address = server_socket.recvfrom(1472)
                print("Mottatt PACKET")
                print(packet)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]
                print("PACKET12:, FLAGS")
                print(packet[:12])
                print(flags)
                if flags == 0:
                    print(f"ADDED DATA TO WORKING FILE IN INDEX " + str(seq))
                    received_data[seq] = data
                    response = create_packet(seq, seq, 4, window, "".encode())
                    server_socket.sendto(response, client_address)
            except Exception as e:
                print(f"Exception ocurred: {e}")




#Main client function, initialises the client with specified parameters
def client(ip, port, filename, reliability, testcase, window_size):
    #ip and port: Which IP-address and port the client should send to
    #filename: path to file to be sent over the program
    #reliability: What reliability protocol should be used for the connection
    #testcase: XXXXX ????

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #Creating socket
    serverAddress = (ip, port)      #The IP:PORT tuple is saved as a variable for simplicity


    #######
    # Threeway handshake for initialising connection
    # The handshake is also used for calculating the RTT and setting the timeout accordingly
    #######
    # 1. Send SYN to server
    print(f"Sending SYN to server", end="\r")
    sequence_number = 1  # Sequence number for packets sent from client
    acknowledgment_number = 0  # ACK number for packets sent from client
    window = 0  # window size
    flags = 8  # SYN flag

    # Create SYN packet
    packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, "".encode())
    start_time = time.time()
    client_socket.sendto(packet, serverAddress)

    # 2. Receive and parse SYN-ACK from server
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)
    if flags == 12:  # If flags == SYN+ACK
        end_time = time.time()
        # 3. Client sends final ACK to server
        packet = header.create_packet(sequence_number, ack, 4, window, "".encode())
        client_socket.sendto(packet, serverAddress)

    #######
    #Set timeout using measured RTT
    #######
    timeout_s = end_time - start_time
    client_socket.settimeout(4*timeout_s)
    print("RTT: " + str(timeout_s) + ". Client socket timeout set to: " + str(4*timeout_s))

    #######
    # Read and prepare the file for transfer
    #######
    # Open file in binary mode and read data
    with open(filename, "rb") as file:
        file_data = file.read()  # Read the contents of the file into a byte string
        file_size = len(file_data)  # Determine size in bytes of the file
        packetsize = 1460  # Size of each packet's payload.
        no_of_packets = int(math.ceil(file_size / packetsize))  # Calculate number of packets this file needs to be split into.

        # Split file into an array where each index contains up to packetsize (1460) bytes
        split_file = []
        for index in range(0, file_size, packetsize):
            split_file.append(file_data[index:index + packetsize])

        # Print file information
        print("Opened file: " + str(filename))  # Print name of the opened file
        print("File size: " + str(file_size) + ", no of packets: " + str(
            no_of_packets))  # Print size of the file and number of packets requiered to send  the file
        print("No of packets: " + str(len(split_file)))  # Print number of packets the file was split into

        #######
        # Create metadata containing the filename, total number of packets and the total file size
        #######
        metadata = pack_metadata(filename, no_of_packets, file_size)
        packet = create_packet(1, 0, 0, window, metadata)

        while True:
            try:
                client_socket.sendto(packet, serverAddress)
                response, null = client_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(response)
                if flags == 4 and ack == 0:
                    print("ACK received for metadata")
                    break
            except Exception as e:
                print("Exception when sending metadata: " + str(e))

        def stop_wait():
            print("stopwait")
            offset = sequence_number  # Sequence_number is not 0 because of previous messages.
            # Sequence_number is used as an offset for i to send the correct seq to server

            for i, packet_data in enumerate(split_file):
                print(f"Sending packet {i} of {no_of_packets}",
                      end="\r")  # Print a progress message of which package is being sent
                # packet = create_packet(i+offset, ack, flags, win, packet_data)
                packet = create_packet(i, 0, 0, window, packet_data)

                # Send packet and wait for ACK
                retries = 0
                while retries <= 3:
                    try:
                        # Send packet to receiver
                        client_socket.sendto(packet, serverAddress)
                        # print(f"Sent packet with sequence number: {i+offset}")
                        print(f"Sent packet with sequence number: {i}")

                        # Receive for ACK
                        response, null = client_socket.recvfrom(1472)
                        print("RESPONSE")
                        print(response)
                        seq, ack, flags, win = parse_header(response)
                        # Check if received ACK is for the expected sequence number
                        # if flags == 4 and ack == i+offset: #If flags = ACK and ack is equal to seq
                        if flags == 4 and ack == i:  # If flags = ACK and ack is equal to seq
                            # print(f"Received ACK for packet with sequence number: {i+offset}")
                            print(f"Received ACK for packet with sequence number: {i}")
                            break
                        # elif flags == 4 and ack == i+offset-1:
                        elif flags == 4 and ack == i - 1:
                            print(f"Received duplicate ACK for packet with previous sequence number: {i + offset - 1}")
                            continue

                    except socket.timeout:
                        retries += 1
                        print(f"Timeout for packet with sequence number: {i}, resending")
                        # Timeout occurred, re-send packet
                        continue

            file.close()
            print("Transfer complete.")

        # Go-Back-N is a protocol that let us send continuous streams of packets without waiting
        # for ACK of the previous packet.
        def gbn(filename):
            client_socket.settimeout(0.5)
            # Read the file data in chunks and send it to the receiver
            seq_num = 0  # Initialize sequence number of the first packet which is going to be sent
            packets = []  # Create empty array list for packets

            while True:
                # Send packets up to window size
                for i in range(window_size):
                    if seq_num >= no_of_packets:
                        break
                    if received_data[seq_num] is None:
                        data = file.read(1460)
                        packet = create_packet(0, seq_num, 4, window_size, data)
                        packets.append(packet)
                        client_socket.sendto(packet, serverAddress)
                        print(f"Sent packet {seq_num}")
                    seq_num += 1

                # Wait for ACK
                    try:
                        packet, serverAddress = client_socket.recvfrom(1472)
                        seq, ack, flags, win = parse_header(packet)

                        if flags == 4 and ack >= 0 and ack < no_of_packets:
                            received_data[ack] = True
                            print(f"Received ACK {ack}")
                            if all(received_data[seq] for seq in range(no_of_packets)):
                                break

                    except client_socket.timeout:
                        print("Socket timeout")

                        # Resend packets in current window
                        for packet in packets:
                            seq, ack, flags, win = parse_header(packet)
                            if received_data[seq] is None:
                                client_socket.sendto(packet, serverAddress)
                                print(f"Resent packet {seq}")
                        break

        # Send each packet with the chosen reliability protocol


        # Sender sends a packet and waits to receive ack. After receiving ack, a new packet will be sendt.
        # If no ack received, it waits for timeout, and tries to send the packet again.

        # SR: Du får ack etter hver eneste pakke.

        # -------- koder ny def sr -----------
        def srny(filename, socket):
            windowSize = 3  # Sets the window size to 3 packets in total

            # Variables
            expSeqNum = 0
            packets = []  # Create array list for packets
            received_packets = {}  # Dictionary to save received packets and their sequence numbers
            # retries = {}  # Dictionary to save the number of retries for each unacknowledged packet
            retries = 0

            while expSeqNum <= len(packets):
                # Sends current window of packets
                windowStart = expSeqNum - windowSize
                windowEnd = min(expSeqNum, len(packets))

                for i in range(windowStart, windowEnd):
                    socket.sendto(packets[i], serverAddress)
                    print(f"Packet with sequence no.{i} sent")
                    retries[i] = 0

                while True:
                    # while retries <= 3
                    try:
                        ackPacket, serverAddress = socket.recvfrom(1472)  # Receive ASK packet from receiver
                        ackSeqNo = extractSeqNo(ackPacket)

                        # Only accept ACK for packets in current window
                        if ackSeqNo >= expSeqNum - windowSize and ackSeqNo < expSeqNum:
                            if ackSeqNo not in received_packets:  # Checks if ACK packet has not been received
                                received_packets[ackSeqNo] = True  # Mark ACK as recived
                                if ackSeqNo in retries:  # Remove packet from retries if it has been acknowledged
                                    del retries[ackSeqNo]
                    except socket.timeout:
                        for sequence_number in retries:
                            if retries < 3:
                                socket.sendto(packets[sequence_number], serverAddress)
                                print(f"Packet with dequence number {sequence_number} is re-sent")
                                retries[sequence_number] += 1
                                # retries += 1
                                break

            print("Transfer complete.")

        def sr_gbn(filename, socket):
            socket.settimeout(0.5)  # Set timeout to 500ms

            # Initialize variables
            expected_seq_num = 0
            next_seq_num = 0  # sends file in chunks
            packets = []  # Create array list for packets
            received_packets = {}  # Dictionary to save received packets and their sequence numbers

            while True:
                # Reads a chunk of data from the fil
                data = file.read(1460)
                if not data:
                    break  # No more data, break loop

                # Create packet with current seq num
                packet = create_packet(next_seq_num, ack, flags, win,
                                       data)  # Creates packet with create_packet() method
                packets.append(packet)  # Add packet to array list
                next_seq_num += 1  # Increases sequence number for next packet

            # Send packet to receiver using both GBN and SR
            while expected_seq_num < len(packets):
                # Send current window of packets
                window_start = expected_seq_num
                window_end = min(window_start + window_size, len(packets))
                for i in range(window_start, window_end):
                    socket.sendto(packets[i], (args.ip, args.port))
                    print(f"Packet with sequence number {i} is sent")

                # Receive ACK from receiver SR
                socket.settimeout(0.5)  # Set timeout to 500ms
                while True:
                    try:
                        ack_packet, serverAddress = socket.recvfrom(1472)  # Receive ACK from receiver
                        ack_seq_num = expected_seq_num(
                            ack_packet)  # Extract sequence number from ACK packet using extract_seq_num() method
                        if ack_seq_num not in received_packets:  # Check if the ACK packet has not been received
                            received_packets[ack_seq_num] = True  # Mark ACK as received
                            if ack_seq_num == expected_seq_num:  # If ACK seq num matches expected
                                expected_seq_num += 1  # Increment expected seq num
                                while expected_seq_num in received_packets:  # If next expected seq num received
                                    expected_seq_num += 1  # If received, increment expected seq num as well
                    except socket.timeout:
                        # Resend UACK packets i window with GBN if timeout
                        print(f"Timeout, resending packets with sequence numbers {window_start} to {window_end}")
                        for i in range(window_start, window_end):
                            if i not in received_packets:
                                socket.sendto(packets[i], (ip, port))
                                print(f"Resent packets with sequence number: {i}")
                        break  # Exit inner loop, resend UACK packets

            print('Transfer complete.')


'''
    # ------- two way handshake ---------
    # Create FIN packet and sends to server
    data = "FIN"
    packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
    client_socket.sendto(packet, serverAddress)
    print("Client is sending a FIN to server to close connection")

    # Receive response and parse header
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)

    # Recives ACK for the FIN and closes connection
    if flags == 4: # If flags == ACK
        print("Received ACK for FIN from server")

        client_socket.close()
        print("Connection closed")

    else:
        print("Error closing connection from client")
    # ----- slutten på two way handshake -------
'''
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
    if os.path.isfile(filename):
        return filename
    else:
        return False

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


def checkTestCase(val):
    val = val.upper()
    if val is None:
        return None
    elif val == "SKIP_ACK" or val == "SKIPACK":
        return "SKIP_ACK"
    elif val == "LOSS":
        return "LOSS"
    else:
        raise Exception("Could not parse -t testcase input. Expected: \"SKIP_ACK\" or \"LOSS\", Actual: " + str(val))

def checkWindow(val):
        val = int(val)
        if not (1 <= val <= 15):
            return False
        else:
            return val


parser = argparse.ArgumentParser(description="positional arguments",
                                 epilog="end of help")  # Initialises argsparse parser

# Arguments
parser.add_argument('-s', '--server', action='store_true', default=False, help="Start in server mode. Default.")
parser.add_argument('-c', '--client', action='store_true', default=False, help="Start in client mode")
parser.add_argument('-i', '--ip', type=checkIP, default="127.0.0.1")
parser.add_argument('-p', '--port', type=checkPort, default="8088", help="Bind to provided port. Default 8088")
### FJERN FØR INNLEVERING: index.html. Bytt til None elns
parser.add_argument('-f', '--file', type=checkFile, default="index.html", help="Path to file to transfer")
parser.add_argument('-r', '--reliable', type=checkReliability, default=None, help="Choose reliable method (GBN or SR)")
parser.add_argument('-t', '--testcase', type=checkTestCase, default=None, help="XXXX")
parser.add_argument('-w', '--windowsize', type=checkWindow, default=5, help="XXXX")
args = parser.parse_args()  # Parses arguments provided by user

if args.server:
    print("starting server")
    server(args.ip, args.port, args.reliable, None, args.windowsize)
elif args.client:
    print("client starting")
    client(args.ip, args.port, args.file, args.reliable, None, args.windowsize)
else:
    print("Could not start")
