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


def server(ip, port, reliability, testcase):
    # creating the socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # This code runs through ports until it finds an open one
    noport = True  # Used for while loop. Set to false when the server successfully binds to a port
    firstPort = port  # Used to quit the program when server can't bind to a provided IP and every port from 1024-65534.
    while noport:  # Loops through all ports for the given IP and binds to the first available one.
        try:  # Used to handle exceptions when server can't bind to a port without quitting the program.
            server_socket.bind((ip, port))  # Attempts to bind with provided IP and current port
            noport = False
        except OSError:  # Excepts error when server cant bind to provided IP and port
            port = port + 1  # Iterates port for the next bind attempt
        if port == 65535:
            port = 1024  # Used to run through remaining ports in the valid range.
        elif (
                port == firstPort - 1):  # If the current port is the one prior to the first port, an error message
            # is shown. It's worth noting that the last port is never actually tested.
            raise Exception("Could not bind to any port on IP " + str(ip))

    print("Server is up and listening on " + str(ip) + ":" + str(port))

    # Wait for a SYN packet from the client
    data, client_address = server_socket.recvfrom(1460)
    seq, ack, flags, win = parse_header(data)
    if flags == 2:  # If SYN packet received
        print("Received SYN from client")

    # Send SYN-ACK packet to client
    sequence_number = 1
    acknowledgment_number = seq + 1
    flags = 12  # SYN-ACK flags
    window = 0
    data = "SYN-ACK".encode()
    packet = create_packet(sequence_number, acknowledgment_number, flags, window, data)
    server_socket.sendto(packet, client_address)
    print("Sent SYN-ACK to client")

    data, client_address = server_socket.recvfrom(1460)
    seq, ack, flags, win = parse_header(data[:12])
    if flags == 4:
            print("ACK has been received, connection established.")


    # While-loop that covers all the functionality of the server
    # The requests it can handle are:
    # PING: Respond to ping from client
    # FILE: Receive file
    sequence_number = 0
    acknowledgment_number = 0
    window = 0
    received_sequence = set()


    while True:
        '''
        '''
        # ---------- Kanskje vi kan kommentere ut fra her! ----------------
        data, client_address = server_socket.recvfrom(1024)
        print("DATA")
        print(data)
        header = data[:12]  # Extract header from message
        data = data [12:]
        seq, ack, flags, win = parse_header(header)
        if "PING" in msg:
            print(f"Received PING from client", end="\r")
            data = "ACK:PING"
            flags = 4  # "ACK" flag 0 1 0 0
            packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
            server_socket.sendto(packet, client_address)

        # ----------------- Til her ettersom SYN-ACK ordner dette? -------------------
        elif "FILE" in msg:
            print("preparing to receive file from client " + str(client_address))
            # Storing indexes in a set as these are more efficient for this use case
            ##Mangler kode for å motta filnavn
            filename = ""
            ########
            # Last index that was received from client. Starts at -1 as the first index is supposed to be 0
            lastIndex = -1
            while True:
                # Server first receives the index
                data, addr = server_socket.recvfrom(1024)
                header = data[:12] # Extract header from message
                seq, ack, flags, win = parse_header(data)
                # If index is "END", the client is done transferring the file
                if flags == 8: #If flags == FIN
                    break
                # Server then receives the payload
                print(f"Recieving chunk " + str(seq), end="\r")

                if lastIndex == int(seq) - 1:
                    # Append incoming data to file variable
                    file += str(data[13:])
                    print("mottatt" + str(seq))
                    ack = create_packet(0, seq, 4, flags, window, None)
                    server_socket.sendto(ack.encode(), client_address)
                elif False:
                    print("hei2")

            # Save file to working directory
            # filename += "received_" + datetime.datetime.now().strftime("%m/%d_%H-%M-%S") + ".txt"
            filename = "received.txt"
            with open(filename, "a+") as f:
                f.write(file)
            print(filename + " saved to working directory.")

        filename = server_socket.recvfrom(1024)  # Receive data from client


        ##### Kommentert ut ettersom dette ikke brukes av programmet (foreløpig?).
        # Open the file , evt use wb to ensure that the data is sent as bytes
        # with open(filename) as f:
        #     while True:
        #         data, serverAddress = server_socket.recvfrom(1024)
        #         if not data:
        #             break
        #         f.write(data)  # Write the received data to the file
        #
        #         if reliability:
        #             # send acknowledgment to client
        #             msg = "ACK".encode()
        #             server_socket.sendto(msg, serverAddress)

        server_socket.close()

        return 0


def client(ip, port, filename, reliability, testcase):
    # creating the socket and server address tuple
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverAddress = (ip, port)

    # Ping server and set client timeout
    client_socket.settimeout(0.5) # Set timeout for client
    done = False # Indicate completion of a task
    timeout = None # Time elapsed between sending a packet and receiven ACK
    sequence_number = 1 # Sequence number for packets being sent
    acknowledgment_number = 0 # ACK number for packets being sent
    window = 0 # window size
    flags = 0 # packet flags

    while not done:
        print(f"Sending SYN to server", end="\r")

        # ------------ Starten på ny kode knyttet til Three-way handshake  -----------------
        # Sender sends a SYN (open; “synchronize
        # sequence numbers”) to receiver

        #Create SYN packet
        data = "SYN"
        packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
        startTime = time.time()
        client_socket.sendto(packet, serverAddress)
        sequence_number += 1

        # Receiver returns a SYN acknowledgment (SYN ACK)

        # Receive response and parse header
        response, null = client_socket.recvfrom(1472)
        seq, ack, flags, win = parse_header(response)


        if flags == 12: # If flags == SYN:ACK
            print("Received SYN ACK from server")

            # Sender sends an ACK to acknowledge the SYN ACK
            # Create ACK packet
            data = "ACK"
            packet = header.create_packet(sequence_number, ack, 4, window, data.encode())
            client_socket.sendto(packet, serverAddress)
            print("Final ACK has been sent to server")

        else:
            print("Error: Expected SYN ACK from server but received unexpected packet")

        # -------------- slutten på ny kode knyttet til Three-way handshake -------------------


        ## FEIL MATTE PÅ TIMEOUT, jeg har gjort noe men vet ikke om det er riktig
        # Create PING packet
        data = "PING"
        packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
        startTime = time.time()
        client_socket.sendto(packet, serverAddress)
        sequence_number += 1

        # Receive response and parse header
        response, null = client_socket.recvfrom(1024)
        seq, ack, flags, win = parse_header(response)



        if flags == 4: #If flags == ACK
            timeout = time.time() - startTime

            # Setting timeout. If RTT is lower than 10ms, timeout is set to a safe low value of 50ms
            # Otherwise, it's set to 4*RTT
            if timeout < 0.01:
                print("RTT is lower than 10ms. Setting client timeout to 50ms. Actual RTT: " + str(round(timeout * 1000, 2)) + "ms")
                client_socket.settimeout(0.5)
            else:
                print("RTT: " + str(round(timeout * 1000, 2)) + "ms. Setting client timeout to " + str(round(4 * timeout * 1000, 2)))
                client_socket.settimeout(4 * timeout)
            done = True
        else:
            print("else. Done: " + str(done))

    # Start file transfer
    done = False

    # Open file in binary mode and read data
    with open(filename, "rb") as file:
        file_data = file.read() # Read the contents of the file into a byte string
        file_size = len(file_data) # Determine size in bytes of the file
        no_of_packets = int(math.ceil(file_size / 1000)) #Calculate number of packets in total for this file in packets of 1000 bytes

        # Split file into packets of max size 1000 bytes
        split_file = []
        for index in range(0, file_size, 1000):
            split_file.append(file_data[index:index+1000])

        # Print file information
        print("Opened file: " + str(filename)) # Print name of the opened file
        print("File size: " + str(file_size) + ", no of packets" + str(no_of_packets)) # Print size of the file and number of packets requiered to send  the file
        print("No of packets: " + str(len(split_file))) # Print number of packets the file was split into

        # Send each packet with the chosen reliability protocol
        for i, packet_data in enumerate(split_file):
            print(f"Sending packet {i+1} of {no_of_packets}", end="\r") # Print a progress message of which package is being sent

            # Send packets with reliability protocol
            if reliability == "SAW":
               sent_packet = stop_wait()
            elif reliability == "GBN":
               sent_packet = gbn() # Send packet using Go-Back-N protocol
            elif reliability == "SR":
               sent_packet = sr() # Send packet using Selective Repeat protocol

    # Sender sends a packet and waits to receive ack. After receiving ack, a new packet will be sendt.
    # If no ack received, it waits for timeout, and tries to send the packet again.
    def stop_wait():
        # Read the file data in chunks and send it to the server
        seq_num = 0
        while True:
            data = file.read(1024)
            if not data:
                break
            packet = create_packet(seq_num, ack, flags, win, data)

            # Send packet and wait for ACK
            while True:
                try:
                    # Send packet to receiver
                    socket.sendto(packet)
                    print(f"Sent packet with sequence number: {seq_num}")

                    # Wait for ACK
                    socket.settimeout(0.5)  # Waits for ack from server
                    ack_packet = socket.recvform(1024)
                    ack_seq_num = extract_seq_num(ack_packet)

                    # Check if received ACK is for the expected sequence number
                    if ack_seq_num == seq_num:
                        print(f"Received ACK for packet with sequence number: {seq_num}")
                        break

                except socket.timeout:
                    print(f"Timeout for packet with sequence number: {seq_num}, resending")
                    # Timeout occurred, re-send packet
                    continue

                    # Move to next sequence number
                    seq_num += 1



        file.close()
        print("Transfer complete.")







# Go-Back-N is a protocol that let us send continuous streams of packets without waiting
# for ACK of the previous packet.
def gbn(filename, socket):
    # Open the file to be transferred
    try:
        file = open(filename, "rb")  # Open file with read and binary mode
    except FileNotFoundError:
        print("Error: Could not open file.")
        return

    # Read the file data in chunks and send it to the receiver
    seq_num = 0 # Initialize sequence number of the first packet which is going to be sent
    packets = [] # Create empty array list for packets
    while True:
        data = file.read(1024)  # Read 1024 bytes of data from the file
        if not data:  # If no data to read, break loop
            break
            packet = create_packet(seq_num, ack, flags, win, data)   # Create packet with current sequence number, and data that has been read
        packets.append(packet)  # Add packet to array list
        seq_num += 1 # Increment sequence of number for next packet
    file.close()  # Close file

    # Send the packets to the receiver using a sliding window
    expected_seq_num = 0  # Initialize expected sequence number of the first ACK received
    window_start = 0  # Initialize start index of current window of packets to be sent
    window_end = min(window_start + 5, len(packets)) # Initialize end index of current window
    while True:
        try:
            # Send the current window of packets
            for i in range(window_start, window_end):
                socket.sendto(packets[i]) # Send packet at index i
                print(f"Sent packet with sequence number: {i}")

            # Receive ACK from the receiver
            ack_packet, address = socket.recvfrom(1024) # Receive packet with an ACK from receiver
            ack_seq_num = extract_seq_num(ack_packet) # Extract sequence number from ACK packet
            if ack_seq_num >= expected_seq_num: # If ACK is for the expected sequence number or a later one
                expected_seq_num = ack_seq_num + 1 # Update the expected sequence number to the next one
                window_start = expected_seq_num # Move start index of the window to next expected sequence number
                window_end = min(window_start + 5, len(packets)) # Move end index of th window to the next one

        except socket.timeout: # If a timeout happens while waiting for ACK
            # An ACK is lost, re-send the current window of packets
            print(f"Timeout, resending packets with sequence numbers {window_start} to {window_end}")
            continue

        if expected_seq_num == len(packets): # If all packets have received ACK
            print("Transfer complete.")
            break

#SR: Du får ack etter hver eneste pakke.
# sends ack for each packet sent
def sr(filename, socket):
    socket.settimeout(0.5)  # Set timeout to 1s
    WINDOW_SIZE = 5  # Set window size to 5 packets

    # Initialize variables
    expected_seq_num = 0
    packets = [] # Create array list for packets
    received_packets = {} # Dictionary to save received packets and their sequence numbers

    # Open the file to be transferred
    try:
        file = open(filename, "rb")
    except FileNotFoundError:
        print("Error: Could not open file.")
        return

    # Read the file data in chunks and send it to the receiver
    seq_num = 0
    while True:
        data = file.read(1024) # Read 1024 bytes of data from file
        if not data: # If there is no data to be read, break loop
            break
            packet = create_packet(seq_num, ack, flags, win, data)   # Create packet
        packets.append(packet) # Add packet to the array list
        seq_num += 1 # Increment sequence number for the next packet
    file.close() # Close the file

    # Send packets to the receiver
    while expected_seq_num < len(packets):
        # Send current window of packets
        window_start = expected_seq_num
        window_end = min(window_start + WINDOW_SIZE, len(packets))
        for i in range(window_start, window_end):
            socket.sendto(packets[i], (args.ip, args.port))

        # Receive ACKs from the receiver
        socket.settimeout(0.5)  # 500 ms timeout for socket operations
        while True:
            try:
                ack_packet, address = socket.recvfrom(1024) # Receive ACK packet from receiver
                ack_seq_num = extract_seq_num(ack_packet) # Exctract sequence number from ACK packet using extract_seq_num() method
                if ack_seq_num not in received_packets: # Check if ACK packet has not been received
                    received_packets[ack_seq_num] = True # Mark ACK as received
                    if ack_seq_num == expected_seq_num: # If ACK sequence number matches expected sequence number
                        expected_seq_num += 1 # Increment expected sequence number
                        while expected_seq_num in received_packets: # Check if next expected packet has been received
                            expected_seq_num += 1 # If received, increment expected sequence number
            except socket.timeout:
                # Timeout occurred, resend unacknowledged packets in window
                break # Exit inner while loop, resend unacknowledged packets


###
# Check-metoder
###

def checkFile(filename):  # Checks if the file exists in the server's system
    if os.path.isfile(filename):
        return True
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
    if val == None:
        return None
    elif val == "SAW" or val == "STOP_AND_WAIT":
        return "SAW"
    elif val == "GBN":
        return "GBN"
    elif val == "SR":
        return "SR"
    else:
        raise Exception(
            "Could not parse -r reliability input. Expected: \"SAW\", \"STOP_AND_WAIT\", \"GBN\" or \"SR\". Actual: " + str(val))

def checkTestCase(val):
    val = val.upper()
    if val == None:
        return None
    elif val == "SKIP_ACK" or val == "SKIPACK":
        return "SKIP_ACK"
    elif val == "LOSS":
        return "LOSS"
    else:
        raise Exception("Could not parse -t testcase input. Expected: \"SKIP_ACK\" or \"LOSS\", Actual: " + str(val))

parser = argparse.ArgumentParser(description="positional arguments", epilog="end of help")  # Initialises argsparse parser

# Arguments
parser.add_argument('-s', '--server', action='store_true', default=False, help="Start in server mode. Default.")
parser.add_argument('-c', '--client', action='store_true', default=False, help="Start in client mode")
parser.add_argument('-i', '--ip', type=checkIP, default="127.0.0.1")
parser.add_argument('-p', '--port', type=checkPort, default="8088", help="Bind to provided port. Default 8088")
### FJERN FØR INNLEVERING: index.html. Bytt til None elns
parser.add_argument('-f', '--file', type=checkFile, default="index.html", help="Path to file to transfer")
parser.add_argument('-r', '--reliable', type=checkReliability, default=None, help="Choose reliable method (GBN or SR)")
parser.add_argument('-t', '--testcase', type=checkTestCase, default=None, help="XXXX")
args = parser.parse_args()  # Parses arguments provided by user

if args.server:
    print("starting server")
    server(args.ip, args.port, None, None)
elif args.client:
    print("client starting")
    client(args.ip, args.port, args.reliability, None, None)
else:
    print("Could not start")
