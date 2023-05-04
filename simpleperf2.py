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
        elif (port == firstPort - 1):  # If the current port is the one prior to the first port, an error message
            # is shown. It's worth noting that the last port is never actually tested.
            raise Exception("Could not bind to any port on IP " + str(ip))

    print("Server is up and listening on " + str(ip) + ":" + str(port))

    # Wait for a SYN packet from the client
    data, client_address = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(data)
    if flags == 8:  # If SYN packet received
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

    # Preparing for file transfer
    filename = ""
    no_of_packets = 0
    expectedFilesize = 0
    received_data = []
    while True:
        # try:
        metadata, client_address = server_socket.recvfrom(1472)
        filename, no_of_packets, expectedFilesize = unpack_metadata(metadata)
        no_of_packets = int(no_of_packets)
        expectedFilesize = int(expectedFilesize)
        sequence_number = 0
        acknowledgment_number = 0
        window = 0
        received_data = [None] * no_of_packets

        response = create_packet(0, 0, 4, window, "".encode())
        server_socket.sendto(response, client_address)
        print("SENT ACK FOR METADATA")
        break
        # except Exception as e:
        #   print("Exception when receiving metadata" + str(e))
    '''
    parse metadata (file name, size, etc) sent from client
    packet, client_address = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(packet)
    data = data[12:]
    if flags == 0:
        '''

    def stop_wait():
        print("I stop_wait")
        for i in range(no_of_packets):
            print("I for " + str(i) + " in no_of_packets: " + str(no_of_packets))
            try:
                print("I try")
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

    if reliability == "SAW":
        stop_wait()
    elif reliability == "GBN":
        gbn()
    elif reliability == "SR":
        sr()
    print(received_data)

    finalFile = ""
    for i, arrayItem in enumerate(received_data):
        print("ARRAYITEM")
        print(arrayItem)
        finalFile += arrayItem.decode()

    f = open(("_recieved.txt"), "w")
    f.write(finalFile)
    f.close()

    # close server
    while True:
        # ----------- two way handshake ---------------
        # Receive response and parse header from client
        data, null = server_socket.recvfrom(1472)
        seq, ack, flags, win = parse_header(data)

        if flags == 2:  # If FIN packet received
            print("Received FIN from client ")

            # Sends a ACK for the FIN
            data = "ACK".encode()
            packet = create_packet(sequence_number, acknowledgment_number, flags, window, data)
            server_socket.sendto(packet, client_address)

            print("ACK has been sent to server, connection is closing")
            server_socket.close()
        else:
            print("Error closing connection from server")
        # ------- slutten på two way handshake -----------

        '''
        # ---------- Kanskje vi kan kommentere ut fra her! ----------------
        data, client_address = server_socket.recvfrom(1472)
        print("DATA")
        print(data)
        header = data[:12]  # Extract header from message
        data = data[12:]
        seq, ack, flags, win = parse_header(header)
        # if "PING" in msg:
        #     print(f"Received PING from client", end="\r")
        #     data = "ACK:PING"
        #     flags = 4  # "ACK" flag 0 1 0 0
        #     packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
        #     server_socket.sendto(packet, client_address)

        # ----------------- Til her ettersom SYN-ACK ordner dette? -------------------
        if "FILE" in data:
            print("preparing to receive file from client " + str(client_address))
            # Storing indexes in a set as these are more efficient for this use case
            ##Mangler kode for å motta filnavn
            filename = ""
            ########
            # Last index that was received from client. Starts at -1 as the first index is supposed to be 0
            lastIndex = -1
            while True:
                # Server first receives the index
                data, addr = server_socket.recvfrom(1472)
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

        filename = server_socket.recvfrom(1472)  # Receive data from client


        ##### Kommentert ut ettersom dette ikke brukes av programmet (foreløpig?).
        # Open the file , evt use wb to ensure that the data is sent as bytes
        # with open(filename) as f:
        #     while True:
        #         data, serverAddress = server_socket.recvfrom(1472)
        #         if not data:
        #             break
        #         f.write(data)  # Write the received data to the file
        #
        #         if reliability:
        #             # send acknowledgment to client
        #             msg = "ACK".encode()
        #             server_socket.sendto(msg, serverAddress)

        server_socket.close()
        '''


def client(ip, port, filename, reliability, testcase):
    # creating the socket and server address tuple
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverAddress = (ip, port)

    # Ping server and set client timeout
    client_socket.settimeout(0.5)  # Set timeout for client
    done = False  # Indicate completion of a task
    timeout = None  # Time elapsed between sending a packet and receiven ACK
    sequence_number = 1  # Sequence number for packets being sent
    acknowledgment_number = 0  # ACK number for packets being sent
    window = 0  # window size
    flags = 0  # packet flags

    print(f"Sending SYN to server", end="\r")

    # ------------ Starten på ny kode knyttet til Three-way handshake  -----------------
    # Sender sends a SYN (open; “synchronize
    # sequence numbers”) to receiver

    # Create SYN packet
    data = "SYN"
    packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
    startTime = time.time()
    client_socket.sendto(packet, serverAddress)
    sequence_number += 1

    # Receiver returns a SYN acknowledgment (SYN ACK)

    # Receive response and parse header
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)

    # Kanksje legge til try catch?
    if flags == 12:  # If flags == SYN:ACK
        # Sender sends an ACK to acknowledge the SYN ACK
        # Create ACK packet
        data = "ACK"
        packet = header.create_packet(sequence_number, ack, 4, window, data.encode())
        client_socket.sendto(packet, serverAddress)
        print("Final ACK has been sent to server")

        try:
            # Wait for final response to print
            final_response, serverAddress = client_socket.recvfrom(1472)
            print("Final response received from server: ", final_response.decode())
        except client_socket.timeout:
            print("Timeout occurred while waiting for final response from server")
            client_socket.close()
            return
    else:
        print("Error: Expected SYN ACK from server but received unexpected packet")
        client_socket.close()
        return

        # -------------- slutten på ny kode knyttet til Three-way handshake -------------------
        ## FEIL MATTE PÅ TIMEOUT, jeg har gjort noe men vet ikke om det er riktig
        # Create PING packet
        # DEPRECATED

        data = "PING"
        packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
        startTime = time.time()
        client_socket.sendto(packet, serverAddress)
        sequence_number += 1

        # Receive response and parse header
        response, null = client_socket.recvfrom(1472)
        seq, ack, flags, win = parse_header(response)

        if flags == 4:  # If flags == ACK
            # timeout = time.time() - startTime
            timeoutDuration = 0.5

            timeout = client_socket.settimeout(timeoutDuration)  # Set timeout for the client

            # test packet
            packet = 'Hello world!'.encode()
            client_socket.sendto(packet, ('127.0.0.1', 8097))

            try:
                # wait for the response and calculates the RTT
                start_time = time.time()
                response, address = client_socket.recvfrom(1472)
                end_time = time.time()
                rtt_time = end_time - start_time  # calculates the RTT time
                print('Response received: ', response.decode())
                print('RTT: ', rtt_time)  # prints the calculated RTT

                # Set timeout, if RTT lower than 10ms, timeout is set to 50ms
                if rtt_time < 0.01:
                    print("RTT is lower than 10ms. Setting timeout to 50ms. RTT: " + str(
                        round(rtt_time * 1000, 2)) + "ms")
                    client_socket.settimeout(0.5)
                else:
                    print("Setting client timeout to " + str(round(4 * rtt_time * 1000, 2)) + " RTT: " + str(
                        round(rtt_time * 1000, 2)) + "ms.")
                    client_socket.settimeout(4 * rtt_time)

            except client_socket.timeout:
                # If timeout occurs, retransmit the packet with adjusted timeout
                print('Timeout occurred, retransmitting packet with adjusted timeout')

                # Create PING packet
                data = "PING"
                packet = header.create_packet(sequence_number, acknowledgment_number, flags, window, data.encode())
                client_socket.sendto(packet, serverAddress)
                sequence_number += 1

                # Update timeout and set it
                try:
                    start_time = time.time()
                    response, address = client_socket.recvfrom(1472)
                    end_time = time.time()
                    rtt_time = end_time - start_time  # calculates the RTT time
                    print('Response received: ', response.decode())
                    print('RTT: ', rtt_time)  # prints the calculated RTT

                    # Setting timeout. If RTT is lower than 10ms, timeout is set to a safe low value of 50ms
                    # Otherwise, it's set to 4*RTT
                    if rtt_time < 0.01:
                        print("RTT is lower than 10ms. Setting client timeout to 50ms. Actual RTT: " + str(
                            round(rtt_time * 1000, 2)) + "ms")
                        client_socket.settimeout(0.5)
                    else:
                        print("RTT: " + str(round(rtt_time * 1000, 2)) + "ms. Setting client timeout to " + str(
                            round(4 * rtt_time * 1000, 2)))
                        client_socket.settimeout(4 * rtt_time)

                except client_socket.timeout:
                    # If timeout occurs again, retransmit the packet with the same timeout value
                    print('Timeout occurred again, retransmitting packet with same timeout')
                    client_socket.sendto(packet, serverAddress)
                    sequence_number += 1
                    client_socket.settimeout(timeout)

    # Start file transfer
    done = False
    print("298. Filename:")
    # Open file in binary mode and read data
    with open(filename, "rb") as file:
        file_data = file.read()  # Read the contents of the file into a byte string
        file_size = len(file_data)  # Determine size in bytes of the file
        packetsize = 1450  # Size of each packet
        no_of_packets = int(math.ceil(
            file_size / packetsize))  # Calculate number of packets in total for this file in packets of 1000 bytes

        # Split file into packets of max size of packetsize bytes
        split_file = []
        for index in range(0, file_size, packetsize):
            split_file.append(file_data[index:index + packetsize])

        # Print file information
        print("Opened file: " + str(filename))  # Print name of the opened file
        print("File size: " + str(file_size) + ", no of packets: " + str(
            no_of_packets))  # Print size of the file and number of packets requiered to send  the file
        print("No of packets: " + str(len(split_file)))  # Print number of packets the file was split into

        client_socket.settimeout(1)

        while True:
            try:
                print("1")
                metadata = pack_metadata(filename, no_of_packets, file_size)
                print("2")
                packet = create_packet(0, 0, 0, window, metadata)
                print("3")
                client_socket.sendto(packet, serverAddress)
                print("4")

                response, null = client_socket.recvfrom(1472)
                print("5")
                seq, ack, flags, win = parse_header(response)
                print("6")
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
        def gbn(filename, socket):
            socket.settimeout(0.5)
            WINDOW_SIZE = 3  # Set window size to 3 packets

            # Read the file data in chunks and send it to the receiver
            seq_num = 0  # Initialize sequence number of the first packet which is going to be sent
            packets = []  # Create empty array list for packets
            while True:
                data = file.read(1460)  # Read 1460 bytes of data from the file
                if not data:  # If no data to read, break loop
                    break
                packet = create_packet(seq_num, 0, 0, WINDOW_SIZE,
                                       data)  # Create packet with current sequence number, and data that has been read
                packets.append(packet)  # Add packet to array list
                seq_num += 1  # Increment sequence of number for next packet

            # Send the packets to the receiver using a sliding window
            expected_seq_num = 0  # Initialize expected sequence number of the first ACK received
            window_start = 0  # Initialize start index of current window of packets to be sent
            window_end = min(window_start + WINDOW_SIZE, len(packets))  # Initialize end index of current window
            while True:
                try:
                    # Send the current window of packets
                    for i in range(window_start, window_end):
                        socket.sendto(packets[i])  # Send packet at index i
                        print(f"Sent packet with sequence number: {i}")

                    # Receive ACK from the receiver
                    ack_packet, address = socket.recvfrom(1472)  # Receive packet with an ACK from receiver
                    ack_seq_num = extract_seq_num(ack_packet)  # Extract sequence number from ACK packet
                    if ack_seq_num >= expected_seq_num:  # If ACK is for the expected sequence number or a later one
                        expected_seq_num = ack_seq_num + 1  # Update the expected sequence number to the next one
                        window_start = expected_seq_num  # Move start index of the window to next expected sequence number
                        window_end = min(window_start + WINDOW_SIZE,
                                         len(packets))  # Move end index of th window to the next one

                except socket.timeout:  # If a timeout happens while waiting for ACK
                    # An ACK is lost, re-send the current window of packets
                    print(f"Timeout, resending packets with sequence numbers {window_start} to {window_end}")
                    continue

                if expected_seq_num == len(packets):  # If all packets have received ACK
                    print("Transfer complete.")
                    break

        # Send each packet with the chosen reliability protocol
        if reliability == "SAW":
            stop_wait()
        elif reliability == "GBN":
            gbn(filename, client_socket)  # Send packet using Go-Back-N protocol
        elif reliability == "SR":
            sr(filename, client_socket)  # Send packet using Selective Repeat protocol

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

        # sends ack for each packet sent
        def sr(filename, socket):
            socket.settimeout(0.5)  # Set timeout to 1s
            WINDOW_SIZE = 3  # Set window size to 3 packets

            # Initialize variables
            expected_seq_num = 0
            packets = []  # Create array list for packets
            received_packets = {}  # Dictionary to save received packets and their sequence numbers
            # Read the file data in chunks and send it to the receiver

            packet = create_packet(expected_seq_num, 0, 0, WINDOW_SIZE, data)  # Create packet
            packets.append(packet)  # Add packet to the array list
            expected_seq_num += 1  # Increment sequence number for the next packet

            # Send packets to the receiver
            while expected_seq_num <= len(packets):
                # Send current window of packets
                window_start = expected_seq_num - WINDOW_SIZE
                window_end = min(expected_seq_num, len(packets))
                for i in range(window_start, window_end):
                    socket.sendto(packets[i], (args.ip, args.port))
                    print(f"Packet with sequence number {i} is sent")

                # Receive ACKs from the receiver
                socket.settimeout(0.5)  # 500 ms timeout for socket operations
                while True:
                    try:
                        ack_packet, serverAddress = socket.recvfrom(1472)  # Receive ACK packet from receiver
                        ack_seq_num = extract_seq_num(
                            ack_packet)  # Exctract sequence number from ACK packet using extract_seq_num() method
                        if ack_seq_num >= expected_seq_num - WINDOW_SIZE and ack_seq_num < expected_seq_num:  # Only accept ACK for UACK packets in current window
                            if ack_seq_num not in received_packets:  # Check if ACK packet has not been received
                                received_packets[ack_seq_num] = True  # Mark ACK as received
                    except socket.timeout:
                        # Timeout occurred, resend unacknowledged packets in window
                        break  # Exit inner while loop, resend unacknowledged packets
                if len(received_packets) == WINDOW_SIZE:  # If all packets in current window have received ACK
                    expected_seq_num += WINDOW_SIZE  # Move window forward
                    received_packets.clear()  # Clear received_packets dictionary for next window

            print("Transfer complete.")

        def sr_gbn(filename, socket):
            socket.settimeout(0.5)  # Set timeout to 500ms
            WINDOW_SIZE = 3  # Set window size to 5 packet

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
                window_end = min(window_start + WINDOW_SIZE, len(packets))
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
                                socket.sendto(packets[i], (args.ip, args.port))
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
args = parser.parse_args()  # Parses arguments provided by user

if args.server:
    print("starting server")
    server(args.ip, args.port, args.reliable, None)
elif args.client:
    print("client starting")
    client(args.ip, args.port, args.file, args.reliable, None)
else:
    print("Could not start")
