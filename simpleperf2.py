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
    acknowledgment_number = seq  # Server acknowledges that packet with sequence_nr is received
    flags = 12  # SYN-ACK flags

    packet = create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
    server_socket.sendto(packet, client_address)
    print("Sent SYN-ACK to client")

    # 3. Receive final ACK from client
    data, client_address = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(data)
    print("Receive final ACK from client")
    print(data)

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
        try:
            metadata, client_address = server_socket.recvfrom(1472)
            print("Receive metadata")
            print(metadata)
            filename, no_of_packets, expectedFilesize = unpack_metadata(metadata)
            no_of_packets = int(no_of_packets)
            expectedFilesize = int(expectedFilesize)
            sequence_number = 0
            acknowledgment_number = 0
            received_data = [None] * no_of_packets

            response = create_packet(0, 0, 4, window_size, "".encode())
            server_socket.sendto(response, client_address)
            print("Sent ACK for metadata")
            break
        except Exception as e:
            raise Exception("Exception when receiving metadata" + str(e))

    print("Out of metadata")

    # Go-Back-N is a protocol that let us send continuous streams of packets without waiting
    # GBN sends packets, and if it loses one of the packets it will delete the packets and send again
    # for ACK of the previous packet.
    def gbn():
        i = 0   # i represents the index that the received packet is supposed to go into in received_data
        while i < no_of_packets: # Runs until every packet from 0 to no_of_packets are received
            done = False
            scope = i + window_size #Scope of window. Used to only receive data from 0 to window_size
            #If the window_size is greater than the remaining amount of packets, set scope to the last index of no_of_packets
            if (scope >= no_of_packets):
                scope = no_of_packets - 1

            while not done: # Used to repeat code until the all the data in the current window has been received succsessfully
                j = i       # Like i, j represents the index of received_data that the server expects to receive.
                while j <= scope: #
                    try:
                        # Receive packet
                        packet, client_address = server_socket.recvfrom(1472)
                        print("GBN")
                        print(packet)
                        seq, ack, flags, win = parse_header(packet)
                        data = packet[12:]
                        if not j == seq:
                            print("Unexpected sequence number: " + str(seq) + ". j: " + str(j))
                            j = i
                            break
                        received_data[seq] = data
                        response = create_packet(seq, seq, 4, window_size, "".encode())
                        server_socket.sendto(response, client_address)
                        print(f"Received index " + str(seq))

                        if j == scope:
                            done = True
                        j += 1

                    except Exception as e:
                        print("Exception when receiving data with GBN: " + str(e))
                        j = i
            i += window_size

    def sr():
        for i in range(no_of_packets):
            try:
                packet, client_address = server_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]
                if seq == i:
                    print(f"ADDED DATA TO WORKING FILE IN INDEX " + str(seq))
                    received_data[seq] = data
                    response = create_packet(seq, seq, 4, window_size, "".encode())
                    server_socket.sendto(response, client_address)
            except Exception as e:
                print(f"Exception occurred: {e}")

    def stop_wait():
        print("I SAW")
        for i in range(no_of_packets):
            try:
                packet, client_address = server_socket.recvfrom(1472)
                print("SAW")
                print(packet)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]
                if seq == i:
                    print(f"ADDED DATA TO WORKING FILE IN INDEX " + str(seq))
                    received_data[seq] = data
                    response = create_packet(seq, seq, 4, window_size, "".encode())
                    server_socket.sendto(response, client_address)
            except Exception as e:
                print(f"Exception occurred: {e}")

    print("RELIABILITY")
    print(reliability)
    if reliability == "SAW":
        print("Starting SAW")
        stop_wait()
    elif reliability == "GBN":
        print("Starting GBN")
        gbn()  # Send packet using Go-Back-N protocol
    elif reliability == "SR":
        sr()

    finalFile = b''
    for i, arrayItem in enumerate(received_data):
        try:
            finalFile += arrayItem
        except Exception as e:
            print("Could not add file with index " + str(i) + " to working file. e: " + str(e))
    filename = filename.replace('\0', '')
    f = open("RECEIVED.TXT", "wb")
    # f = open((f'received_{str(filename)}'), "wb")
    f.write(finalFile)
    f.close()

    # Clear last line and print completion message.
    print("                                                                      ")
    print("Successfully saved file as " + str(filename))

    # close server
    # A two-way handshake to close the connection
    # sends an ACK to acknowledge the SYN ACK from the client
    # ----------- two way handshake ---------------
    # Receive response and parse header from client
    data, null = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(data)
    print(f"Flag: {flags}")

    if flags == 2:  # If FIN packet received
        print("Received FIN from client ")

        # Sends a ACK for the FIN
        sequence_number = 0
        acknowledgment_number = seq  # Server acknowledges that packet with sequence_nr is received
        flags = 6  # FIN-ACK flags

        packet = create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
        server_socket.sendto(packet, client_address)

        print(f"Inn i if statment. Flag: {flags}")
        print("ACK has been sent to client, connection is closing")
        server_socket.close()
    else:
        print("Error closing connection from server")
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
    print(f"Sending SYN to server")
    sequence_number = 1  # Sequence number for packets sent from client
    acknowledgment_number = 0  # ACK number for packets sent from client
    flags = 8  # SYN flag

    # Create SYN packet
    packet = header.create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
    start_time = time.time()
    client_socket.sendto(packet, serverAddress)
    print(f"A SYN-packet has been sent from client to server")

    # 2. Receive and parse SYN-ACK from server
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)
    print(f"SYN-ACK has been received from server")
    if flags == 12:  # If flags == SYN+ACK
        end_time = time.time()

        # 3. Client sends final ACK to server
        packet = header.create_packet(sequence_number, ack, 4, window_size, "".encode())
        client_socket.sendto(packet, serverAddress)
        print(f"Client has sent a final ack and is connecting")

    #######
    # Set timeout using measured RTT
    #######
    timeout_s = end_time - start_time
    client_socket.settimeout(4 * timeout_s)
    print("RTT: " + str(timeout_s) + ". Client socket timeout set to: " + str(4 * timeout_s))

    #######
    # Read and prepare the file for transfer
    #######
    # Initialising variables
    file_data = None
    file_size = 0
    packetsize = 1460  # Size of each packet's payload.
    no_of_packets = 0
    split_file = []

    # Open file in binary mode and read data
    with open(filename, "rb") as file:
        file_data = file.read()  # Read the contents of the file into a byte string
        file_size = len(file_data)  # Determine size in bytes of the file
        # no_of_packets = int(math.ceil(file_size / packetsize))  # Calculate number of packets this file needs to be split into.

        # Split file into an array where each index contains up to packetsize (1460) bytes
        for index in range(0, file_size, packetsize):
            split_file.append(file_data[index:index + packetsize])

        no_of_packets = len(split_file)

        # Print file information
        # print("Opened file: " + str(filename))  # Print name of the opened file
        # print("File size: " + str(file_size) + ", no of packets: " + str(no_of_packets))  # Print size of the file and number of packets requiered to send  the file
        # print("No of packets: " + str(len(split_file)))  # Print number of packets the file was split into

        #######
        # Create metadata containing the filename, total number of packets and the total file size
        #######
        metadata = pack_metadata(filename, no_of_packets, file_size)
        packet = create_packet(1, 0, 0, window_size, metadata)

        while True:
            try:
                client_socket.sendto(packet, serverAddress)
                response, null = client_socket.recvfrom(1472)
                print("METADATA")
                print(response)
                seq, ack, flags, win = parse_header(response)
                if flags == 4 and ack == 0:
                    print("ACK received for metadata")
                    break
            except Exception as e:
                print("Exception when sending metadata: " + str(e))

    def stop_wait():
        offset = sequence_number  # Sequence_number is not 0 because of previous messages.
        # Sequence_number is used as an offset for i to send the correct seq to server

        for i, packet_data in enumerate(split_file):
            print(f"Sending packet {i} of {no_of_packets - 1}",
                  end="\r")  # Print a progress message of which package is being sent
            # packet = create_packet(i+offset, ack, flags, win, packet_data)
            packet = create_packet(i, 0, 0, window_size, packet_data)

            # Send packet and wait for ACK
            retries = 0
            while retries <= 2 * no_of_packets:  # Dynamically scales allowed amount of retries based on filesize
                try:
                    # Send packet to receiver
                    client_socket.sendto(packet, serverAddress)
                    # print(f"Sent packet with sequence number: {i+offset}")
                    print(f"Sent packet with sequence number: {i}")

                    # Receive ACK
                    response, null = client_socket.recvfrom(1472)
                    print("RECV")
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
                        print(f"Received duplicate ACK for packet with previous sequence number: {i - 1}")
                        continue

                except socket.timeout:
                    retries += 1
                    print(f"Timeout for packet with sequence number: {i}, resending")
                    # Timeout occurred, re-send packet
                    continue

    # Go-Back-N is a protocol that let us send continuous streams of packets without waiting
    # for ACK of the previous packet.
    def gbn(serverAddress):
        i = 0
        # for i in range (0, no_of_packets-1, window_size):
        while i <= no_of_packets - 1:
            done = False  # Used to run until all packets are sent
            scope = i + window_size
            if i + window_size >= no_of_packets:
                scope = no_of_packets - 1
            while not done:
                j = i
                while j <= scope:
                    # for j in range (i, scope, 1):
                    if j > no_of_packets - 1:
                        print("Outside of split_file index")
                        break
                    data = split_file[j]
                    packet = create_packet(j, 0, 0, window_size, data)
                    try:
                        # Send packet to receiver
                        client_socket.sendto(packet, serverAddress)
                        # print(f"Sent packet with sequence number: {i+offset}")
                        print(f"Sent packet with sequence number: {j}")

                        # Receive ACK
                        response, null = client_socket.recvfrom(1472)
                        seq, ack, flags, win = parse_header(response)
                        # Check if received ACK is for the expected sequence number
                        # if flags == 4 and ack == i+offset: #If flags = ACK and ack is equal to seq
                        if flags == 4 and ack == j:  # If flags = ACK and ack is equal to seq
                            # print(f"Received ACK for packet with sequence number: {i+offset}")
                            print(f"Received ACK for packet with sequence number: {ack}")
                            j += 1
                            if j == no_of_packets - 1 or j == i + window_size:
                                done = True
                        # elif flags == 4 and ack == i+offset-1:
                        elif not ack == j:
                            print("Received unexpected ack: " + str(ack) + ". j: " + str(j))
                        else:
                            print(f"Received unexpected response with sequence number: {ack}")

                    except Exception as e:
                        print("Issue when sending packet using GBN: " + str(e))
                        j = i
            i += window_size
    def sr():
        i = 0
        while i <= no_of_packets - 1:
            failed_packets = []
            scope = i + window_size
            if scope >= no_of_packets:
                scope = no_of_packets - 1
            j = i
            while j <= scope:
                if j > no_of_packets - 1:
                    print("Outside of split_file index")
                    break
                data = split_file[j]
                packet = create_packet(j, 0, 0, window_size, data)
                try:
                    # Send packet to receiver
                    client_socket.sendto(packet, serverAddress)
                    print(f"Sent packet with sequence number: {j}")

                    # Receive ACK
                    response, null = client_socket.recvfrom(1472)
                    seq, ack, flags, win = parse_header(response)
                    # Check if received ACK is for the expected sequence number
                    # if flags == 4 and ack == i+offset: #If flags = ACK and ack is equal to seq
                    if flags == 4 and ack == j:  # If flags = ACK and ack is equal to seq
                        # print(f"Received ACK for packet with sequence number: {i+offset}")
                        print(f"Received ACK for packet with sequence number: {ack}")
                        j += 1
                        if j == no_of_packets - 1 or j == i + window_size:
                            break
                    elif not ack == j:
                        print("Received unexpected ack: " + str(ack) + ". j: " + str(j))
                    else:
                        print(f"Received unexpected response with sequence number: {ack}")

                except Exception as e:
                    print("Issue when sending packet using SR: " + str(e))
                    failed_packets.append(j) # Stores the index of the packet that was not sent successfully
                    j = i

                while len(failed_packets) > 0:
                    print("Resending failed packet i: " +str(failed_packets[0]))
                    j = failed_packets[0]
                    data = split_file[j]
                    packet = create_packet(j, 0, 0, window_size, data)
                    try:
                        # Send packet to receiver
                        client_socket.sendto(packet, serverAddress)
                        print(f"Sent packet with sequence number: {j}")

                        # Receive ACK
                        response, null = client_socket.recvfrom(1472)
                        seq, ack, flags, win = parse_header(response)
                        # Check if received ACK is for the expected sequence number
                        if flags == 4 and ack == j:  # If flags = ACK and ack is equal to seq
                            print(f"Received ACK for packet with sequence number: {ack}")

                        elif not ack == j:
                            print("Received unexpected ack: " + str(ack) + ". j: " + str(j))
                        else:
                            print(f"Received unexpected response with sequence number: {ack}")
                        failed_packets.pop(0)
                    except Exception as e:
                        print("Exception: " +str(e))

            i += window_size

    # Sender sends a packet and waits to receive ack. After receiving ack, a new packet will be sendt.
    # If no ack received, it waits for timeout, and tries to send the packet again.

    # SR: Du får ack etter hver eneste pakke.

    def hybrid(serverAddress):
        i = 0
        while i <= no_of_packets - 1:
            done = False
            scope = i + window_size
            if i + window_size >= no_of_packets:
                scope = no_of_packets - 1
            packets_sent = []
            while not done:
                j = i
                while j <= scope:
                    if j > no_of_packets - 1:
                        print("Outside of split_file index")
                        break
                    if j not in packets_sent:
                        data = split_file[j]
                        packet = create_packet(j, 0, 0, window_size, data)
                        try:
                            client_socket.sendto(packet, serverAddress)
                            print(f"Sent packet with sequence number: {j}")
                            packets_sent.append(j)
                        except Exception as e:
                            print("Issue when sending packet using hybrid method: " + str(e))
                    j += 1
                try:
                    client_socket.settimeout(0.5) # set a timeout for receiving ACKs
                    while True:
                        response, null = client_socket.recvfrom(1472)
                        seq, ack, flags, win = parse_header(response)
                        if flags == 4 and ack in packets_sent:
                            print(f"Received ACK for packet with sequence number: {ack}")
                            packets_sent.remove(ack)
                            if not packets_sent:
                                done = True
                except socket.timeout:
                    # no ACK received within timeout, switch to GBN
                    for packet_number in packets_sent:
                        data = split_file[packet_number]
                        packet = create_packet(packet_number, 0, 0, window_size, data)
                        try:
                            client_socket.sendto(packet, serverAddress)
                            print(f"Retransmitted packet with sequence number: {packet_number} using GBN")
                        except Exception as e:
                            print("Issue when sending packet using hybrid method: " + str(e))
                    # wait for GBN to complete transmission
                    try:
                        while True:
                            response, null = client_socket.recvfrom(1472)
                            seq, ack, flags, win = parse_header(response)
                            if flags == 4 and ack in packets_sent:
                                print(f"Received ACK for packet with sequence number: {ack} using GBN")
                                packets_sent.remove(ack)
                                if not packets_sent:
                                    done = True
                            elif not ack in packets_sent:
                                print(f"Received unexpected ACK with sequence number: {ack} using GBN")
                    except socket.timeout:
                        # no more ACKs received, switch back to SR
                        break
            i += window_size


    # Send file with chosen reliability protocol
    if reliability == "SAW":
        stop_wait()
    elif reliability == "GBN":
        gbn(serverAddress)  # Send packet using Go-Back-N protocol
    elif reliability == "SR":
        sr()  # Send packet using Selective Repeat protocol

    file.close()

    # Clear last line and print completion message.
    print("                                                                      ")
    print("Transfer complete.")

    # ------- two way handshake ---------
    # ends the connection with a two-way handshake
    # Create FIN packet and sends to server
    sequence_number = 0
    acknowledgment_number = seq  # Server acknowledges that packet with sequence_nr is received
    flags = 2  # FIN flags

    packet = header.create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
    client_socket.sendto(packet, serverAddress)
    print("Client is sending a FIN to server to close connection")

    # Receive response and parse header
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)
    print(f"Flag i client for å check FIN ACK: {flags}")

    # Recives ACK for the FIN and closes connection
    if flags == 6: # If flags == ACK
        print("Received ACK for FIN from server")

        client_socket.close()
        print("Connection closed")

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
    elif val == "SKIP_SEQ" or val == "SKIPSEQ":
        return "SKIP_SEQ"
    elif val == "LOSS":
        return "LOSS"
    else:
        raise Exception(
            "Could not parse -t testcase input. Expected: \"SKIP_ACK\", \"SKIP_SEQ\" or \"LOSS\", Actual: " + str(val))


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
parser.add_argument('-i', '--ip', type=checkIP, default="127.0.0.1")
parser.add_argument('-p', '--port', type=checkPort, default="8088", help="Bind to provided port. Default 8088")
### FJERN FØR INNLEVERING: index.html. Bytt til None elns
parser.add_argument('-f', '--file', type=checkFile, default=None, help="Path to file to transfer")
parser.add_argument('-r', '--reliable', type=checkReliability, default="SAW", help="Choose reliable method (GBN or SR)")
parser.add_argument('-t', '--testcase', type=checkTestCase, default=None, help="XXXX")
parser.add_argument('-w', '--windowsize', type=checkWindow, default=5, help="XXXX")
args = parser.parse_args()  # Parses arguments provided by user

if args.server:
    print("Starting in server mode")
    server(args.ip, args.port, args.reliable, None, args.windowsize)
elif args.client:
    print("Starting in client mode")
    client(args.ip, args.port, args.file, args.reliable, None, args.windowsize)
else:
    print("Could not start the program")
