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

    # While-loop that covers all the functionality of the server
    # The requests it can handle are:
    # PING: Respond to ping from client
    # FILE: Receive file
    sequence_number = 0
    acknowledgment_number = 0
    window = 0
    received_sequence = set()

    while True:
        data, client_address = server_socket.recvfrom(1024)
        print("DATA")
        print(data)
        header = data[:12]  # Extract header from message
        seq, ack, flags, win = parse_header(data)
        if "PING" in msg:
            print(f"Received PING from client", end="\r")
            data = "ACK:PING"
            flags = 4  # "ACK" flag 0 1 0 0
            packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())

            server_socket.sendto(packet, client_address)
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
    client_socket.settimeout(0.5)
    done = False
    timeout = None
    sequence_number = 1
    acknowledgment_number = 0
    window = 0
    flags = 0

    while not done:
        print(f"Pinging server", end="\r")

        ## FEIL MATTE PÅ TIMEOUT
        data = "PING"
        packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
        startTime = time.time()
        client_socket.sendto(packet, serverAddress)
        sequence_number += 1
        response, null = client_socket.recvfrom(1024)
        seq, ack, flags, win = parse_header(response)

        if flags == 4: #If flags == ACK
            timeout = time.time() - startTime

            # Setting timeout. If RTT is lower than 10ms, timeout is set to a safe low value of 50ms
            # Otherwise, it's set to 4*RTT
            if timeout < 0.01:
                print("RTT is lower than 10ms. Setting client timeout to 50ms. Actual RTT: " + str(round(timeout * 1000, 2)) + "ms")
                client_socket.settimeout(0.05)
            else:
                print("RTT: " + str(round(timeout * 1000, 2)) + "ms. Setting client timeout to " + str(round(4 * timeout * 1000, 2)))
                client_socket.settimeout(4 * timeout)
            done = True
        else:
            print("else. Done: " + str(done))

    # Start file transfer
    done = False
    file = open("index.html", "rb")
    while not done:
        print(f"Sending chunk " + str(index), end="\r")
        data = file.read(1000)  # Transfer 1000 bytes at a time, reserving 24 out of 1024 bytes for index
        if not data:
            done = True
            break

        print("SEQ NR:")
        print(sequence_number)
        print("DATA:")
        print(data)
        # chunk = (index, data)
        # chunk = bytes(str(chunk), "utf-8")
        # client_socket.sendto(chunk, serverAddress)
        # print(chunk.decode("utf-8"))



        ## STILIAN fortsett herfra <33333 xoxo
        # Creates DRTP header and sends the packet to the server
        packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
        client_socket.sendto(packet, serverAddress)
        sequence_number += 1

        response, null = client_socket.recvfrom(1024)
        expectedResponse = "ACK:" + str(index)
        if not response.decode() == expectedResponse:
            print("send ACK REQ på nytt")

    # Sends "END" when file transfer is done
    client_socket.sendto("END".encode(), serverAddress)
    print("Sent file index.html to " + str(serverAddress))

    return 0


def make_packet(seq_num, data):
    # Make a packet with the sequence number and data
    return struct.pack("I1024s", seq_num, data)


def extract_seq_num(packet):
    # Extract the sequence number from the packet received
    return struct.unpack("I", packet[:4])[0]


# Sender sends a packet and waits to receive ack. After receiving ack, a new packet will be sendt.
# If no ack received, it waits for timeout, and tries to send the packet again.
def stop_wait(filename, socket):
    # Open the file to be transferred
    try:
        file = open(filename, "rb")
    except FileNotFoundError:
        print("Error: Could not open file.")
        return

    # Read the file data in chunks and send it to the server
    seq_num = 0
    while True:
        data = file.read(1024)
        if not data:
            break
        packet = make_packet(seq_num, data)

        # Send packet and wait for ACK
        while True:
            try:
                # Send packet to receiver
                socket.sendto(packet)
                print(f"Sent packet with sequence number: {seq_num}")

                # Wait for ACK
                socket.settimeout(1)  # Waits for ack from server
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
        file = open(filename, "rb")
    except FileNotFoundError:
        print("Error: Could not open file.")
        return

    # Read the file data in chunks and send it to the receiver
    seq_num = 0
    packets = []
    while True:
        data = file.read(1024)
        if not data:
            break
        packet = make_packet(seq_num, data)
        packets.append(packet)
        seq_num += 1
    file.close()

    # Send the packets to the server
    expected_seq_num = 0
    window_start = 0
    window_end = min(window_start + 5, len(packets))
    while True:
        try:
            # Send the current window of packets
            for i in range(window_start, window_end):
                socket.sendto(packets[i])
                print(f"Sent packet with sequence number: {i}")

            # Receive ACK from the receiver
            ack_packet, address = socket.recvfrom(1024)
            ack_seq_num = extract_seq_num(ack_packet)
            if ack_seq_num >= expected_seq_num:
                expected_seq_num = ack_seq_num + 1
                window_start = expected_seq_num
                window_end = min(window_start + 5, len(packets))

        except socket.timeout:
            # An ACK is lost, re-send the current window of packets
            print(f"Timeout, resending packets with sequence numbers {window_start} to {window_end}")
            continue

        if expected_seq_num == len(packets):
            print("Transfer complete.")
            break


def sr(filename, socket):
    socket.settimeout(1)  # Set timeout to 1s
    WINDOW_SIZE = 5  # Set window size to 5 packets

    # Initialize variables
    expected_seq_num = 0
    packets = []
    received_packets = {}

    # Open the file to be transferred
    try:
        file = open(filename, "rb")
    except FileNotFoundError:
        print("Error: Could not open file.")
        return

    # Read the file data in chunks and send it to the receiver
    seq_num = 0
    while True:
        data = file.read(1024)
        if not data:
            break
        packet = make_packet(seq_num, data)
        packets.append(packet)
        seq_num += 1
    file.close()

    # Send packets to the receiver
    while expected_seq_num < len(packets):
        # Send current window of packets
        window_start = expected_seq_num
        window_end = min(window_start + WINDOW_SIZE, len(packets))
        for i in range(window_start, window_end):
            socket.sendto(packets[i], (args.ip, args.port))

        # Receive ACKs from the receiver
        socket.settimeout(0.5)  # 500 ms timeout
        while True:
            try:
                ack_packet, address = socket.recvfrom(1024)
                ack_seq_num = extract_seq_num(ack_packet)
                if ack_seq_num not in received_packets:
                    received_packets[ack_seq_num] = True
                    if ack_seq_num == expected_seq_num:
                        expected_seq_num += 1
                        while expected_seq_num in received_packets:
                            expected_seq_num += 1
            except socket.timeout:
                # Timeout occurred, resend unacknowledged packets in window
                break


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

parser = argparse.ArgumentParser(description="positional arguments",
                                 epilog="end of help")  # Initialises argsparse parser

# Arguments
parser.add_argument('-s', '--server', action='store_true', default=False, help="Start in server mode. Default.")
parser.add_argument('-c', '--client', action='store_true', default=False, help="Start in client mode")
parser.add_argument('-i', '--ip', type=checkIP, default="127.0.0.1")
parser.add_argument('-p', '--port', type=checkPort, default="8088", help="Bind to provided port. Default 8088")
parser.add_argument('-f', '--file', type=checkFile, default=None, help="Path to file to transfer")
parser.add_argument('-r', '--reliable', type=checkReliability, default=None, help="XXXX")
parser.add_argument('-t', '--testcase', type=checkTestCase, default=None, help="XXXX")
args = parser.parse_args()  # Parses arguments provided by user

if args.server:
    print("starting server")
    server(args.ip, args.port, None, None)
elif args.client:
    print("client starting")
    client(args.ip, args.port, None, None, None)
else:
    print("Could not start")
