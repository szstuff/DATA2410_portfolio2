import socket
import argparse
import re
import time
import os
try: #Checks if header.py is accessible
    from header import *
except:
    raise Exception("Could not import dependencies. Confirm that header.py is available in the same directory as the application")


# initialises the server with specified parameters
def server(ip, port, reliability, testcase, window_size):
    # ip and port: Which IP-address and port the server should listen to
    # reliability: What reliability protocol should be used for the connection
    # testcase: Which artificial testcase to use when receiving, if any.
    # window_size: What window size to use for SR and GBN

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # creating the socket
    # This code runs through ports until it finds an open one
    firstPort = port  # Used to quit the program when server can't bind to a provided IP and every port from 1024-65534.
    while True:  # Loops through all ports for the given IP and binds to the first available one.
        try:
            server_socket.bind((ip, port))  # Attempts to bind with provided IP and current port
            break  # Break out of loop if bind didn't raise an exception
        except OSError:
            port = port + 1  # Iterates port for the next bind attempt
        if port == 65535:
            port = 1024
        elif (port == firstPort - 1):  # raise exception when all ports are busy
                                        #TODO: final port is never checked
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
        raise Exception("Expected ACK (4) packet. Received: " + str(flags))

    ########
    # Receive metadata from client
    ########
    filename = ""
    no_of_packets = 0
    received_data = []
    print("##### Preparing to receive metadata")
    while True:
        try:
            metadata, client_address = server_socket.recvfrom(1472)  # Wait for packet to arrive
            filename, no_of_packets = unpack_metadata(
                metadata)  # Extract metadata from received packet
            no_of_packets = int(no_of_packets)  # Convert no_of_packets into int
            sequence_number = 0
            acknowledgment_number = 0
            received_data = [None] * (no_of_packets)

            response = create_packet(0, 0, 4, window_size, "".encode())  # Create ACK packet
            server_socket.sendto(response, client_address)  # Send ACK packet
            break
        except Exception as e:
            raise Exception("Exception when receiving metadata" + str(e))

    def gbn(): #Starts file transfer using GBN
        testcase_not_run = True # Used to skip ack only once when a testcase is set
        seq_num_tracker = 0     # Tracks sequence number that is expected from the client

        # Loop until every packet is received
        while seq_num_tracker < no_of_packets:
            try:
                # Receive packet, parse header and separate data from header
                packet, client_address = server_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]

                # Add the data to the file at its correct index
                received_data[seq] = data

                # If the sequence number is not as expected, a packet has
                # been lost and seq_num_tracker needs to be updated
                if not seq_num_tracker == seq:
                    seq_num_tracker = seq

                #Skips ACK for sequence 3 if testcase is set to SKIP_ACK
                if seq_num_tracker == 3 and testcase_not_run and testcase == "SKIP_ACK":
                    testcase_not_run = False
                    seq_num_tracker += 1
                    continue #Skip the rest of the code in the loop to simulate a lost packet

                response = create_packet(seq, seq, 4, window_size, "".encode())
                server_socket.sendto(response, client_address)
                seq_num_tracker += 1

            except Exception as e:
                print(f"Exception occurred: {e}")

    ##This is our newer, modified version of GBN.
    def gbnv2():
        seqNumTracker = -1  # Tracks the sequence number of the last packet received
        testcaseNotRun = True  # Flag to indicate if the testcase has been executed or not

        # Loop through every packet that is received
        while seqNumTracker < no_of_packets - 1:
            try:
                # Receive packet
                packet, client_address = server_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]

                if seq <= seqNumTracker:  # If the received packet is a duplicate, ignore it
                    continue

                # Add the data to the file at its correct index
                received_data[seq] = data

                # Check if the received packet's sequence number is the expected next sequence number
                if seqNumTracker + 1 == seq:
                    seqNumTracker += 1  # Increase the sequence number tracker by 1

                    # If the sequence number tracker reaches 3 and the testcase is set to "SKIP_ACK" and the testcase flag indicates it has not been executed yet
                    if seqNumTracker == 3 and testcase == "SKIP_ACK" and testcaseNotRun:
                        seq = 4  # Skip the acknowledgement for the next packet (simulate a skipped acknowledgement)
                        testcaseNotRun = False  # Set the testcase flag to indicate it has been executed
                else:
                    continue  # If the received packet is not the expected next sequence number, continue to the next iteration of the loop

                # Send ACK
                if seqNumTracker == seq:
                    # Create an ACK packet with the same sequence number as the received packet
                    response = create_packet(seq, seq, 4, window_size, "".encode())
                    server_socket.sendto(response, client_address)
                else:
                    # Create an ACK packet with the expected sequence number
                    response = create_packet(seq, seq, 4, window_size, "".encode())
                    server_socket.sendto(response, client_address)
                    seqNumTracker -= 1

            except:
                print("An error occurred")


    def sr(): #Starts file transfer using SR
        testcase_not_run = True # Used to skip ack only once when a testcase is set
        seq_num_tracker = 0     # Tracks sequence number that is expected from the client

        # Loop until every packet is received
        while seq_num_tracker < no_of_packets:
            try:
                # Receive packet, parse header and separate data from header
                packet, client_address = server_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]

                # Add the data to the file at its correct index
                received_data[seq] = data

                # If the sequence number is not as expected, a packet has
                # been lost and seq_num_tracker needs to be updated
                if not seq_num_tracker == seq:
                    seq_num_tracker = seq

                #Skips ACK for sequence 3 if testcase is set to SKIP_ACK
                if seq_num_tracker == 3 and testcase_not_run and testcase == "SKIP_ACK":
                    testcase_not_run = False
                    seq_num_tracker += 1
                    continue #Skip the rest of the code in the loop to simulate a lost packet

                response = create_packet(seq, seq, 4, window_size, "".encode())
                server_socket.sendto(response, client_address)
                seq_num_tracker += 1

            except Exception as e:
                print(f"Exception occurred: {e}")

    ##This is our newer, modified version of SR.
    def srv2():
        testcaseNotRun = True  # Flag to indicate if the testcase has been executed or not
        seqNumTracker = 0  # Tracks the sequence number of the last packet received

        # Loop through every packet that is received
        while seqNumTracker < no_of_packets:
            try:
                # Receive packet
                packet, client_address = server_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]

                # Add the data to the file at its correct index
                received_data[seq] = data

                # Check if the received packet's sequence number is not equal to the expected sequence number
                if not seqNumTracker == seq:
                    seqNumTracker = seq  # Update the sequence number tracker

                # Check if the sequence number tracker is 3, testcase has not been executed, and the testcase is set to "SKIP_ACK"
                if seqNumTracker == 3 and testcaseNotRun and testcase == "SKIP_ACK":
                    testcaseNotRun = False  # Set the testcase flag to indicate it has been executed
                    seqNumTracker += 1  # Increase the sequence number tracker
                    continue  # Skip to the next iteration of the loop

                # Create an ACK packet with the same sequence number as the received packet
                response = create_packet(seq, seq, 4, window_size, "".encode())
                server_socket.sendto(response, client_address)  # Send the ACK packet

                seqNumTracker += 1  # Increase the sequence number tracker

            except Exception as e:
                # Handle any exceptions that occur during packet reception or ACK sending
                print(f"Exception occurred: {e}")

    def stop_wait(): #Starts file transfer using Stop and Wait
        testcase_not_run = True # Used to skip ack only once when a testcase is set
        i = 0

        # Iterate through every expected packet
        while i < no_of_packets:
            try:
                # Receive packet, parse header and separate data from header
                packet, client_address = server_socket.recvfrom(1472)
                seq, ack, flags, win = parse_header(packet)
                data = packet[12:]

                # Add the data to the file at its correct index
                received_data[seq] = data

                # If the sequence number is not as expected, a packet has
                # been lost and seq_num_tracker needs to be updated
                if not i == seq:
                    i = seq

                #Skips ACK for sequence 3 if testcase is set to SKIP_ACK
                if seq == i:  # If the received sequence number matches the expected sequence number
                    if i == 3 and testcase_not_run and testcase == "SKIP_ACK":
                        testcase_not_run = False
                        i += 1
                        continue #Skip the rest of the code in the loop to simulate a lost packet

                response = create_packet(seq, seq, 4, window_size, "".encode())  # Create an ACK packet
                server_socket.sendto(response, client_address)  # Send the ACK packet to client
                i += 1

            except Exception as e:
                print(f"Exception occurred: {e}")

    if reliability == "SAW":
        print("##### Starting file transfer using Stop and Wait protocol")
        stop_wait()  # Send packet using Stop-And-Wait
    elif reliability == "GBN":
        print("##### Starting file transfer using Go-Back-N protocol")
        gbn()  # Send packet using Go-Back-N protocol
    elif reliability == "GBNV2":
        print("##### Starting file transfer using version 2 of the Go-Back-N protocol")
        gbnv2()
    elif reliability == "SR":
        print("##### Starting file transfer using Selective Repeat protocol")
        sr()  # Send packet using Selective-Repeat
    elif reliability == "SRV2":
        print("##### Starting file transfer using version 2 of the Selective Repeat protocol")
        srv2()

    final_file = b''  # Empty bytes object to hold joined file data
    print("##### Saving file to disk")
    # Iterate through received_data array and add packets to final_file
    for i, array_item in enumerate(received_data):
        try:
            final_file += array_item
        except Exception as e:
            print("Could not add file with index " + str(i) + " to working file. e: " + str(e))

    # Remove any null bytes in the filename and add "received_" to the start of the filename
    filename = filename.replace('\0', '')
    filename = "received_" + str(filename)

    # Save the concatenated file to disk
    f = open(f'received_{filename}', "wb")
    f.write(final_file)
    f.close()

    print("##### Successfully saved file as " + str(filename))

    ########
    # Close server with two-way handshake
    ########
    # Receive response and parse header from client
    print("Receiving two-way handshake")
    data, null = server_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(data)

    if flags == 2:  # If FIN packet received
        # Sends an ACK for the FIN
        sequence_number = 0
        acknowledgment_number = seq  # Server acknowledges that packet with sequence_nr is received
        flags = 6  # FIN-ACK flags

        packet = create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
        server_socket.sendto(packet, client_address)
        server_socket.close()
        print("##### Connection closed")
    else:
        raise Exception("Error closing connection")


# Main client function, initialises the client with specified parameters
def client(ip, port, filename, reliability, testcase, window_size):
    # ip and port: Which IP-address and port the client should send to
    # filename: path to file to be sent over the program
    # reliability: What reliability protocol should be used for the connection
    # testcase: Which artificial testcase to use when sending, if any.
    # window_size: What window size to use for SR and GBN

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
    packet = create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
    start_time = time.time()
    client_socket.sendto(packet, serverAddress)

    # 2. Receive and parse SYN-ACK from server
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)
    if flags == 12:  # If flags == SYN+ACK
        end_time = time.time()

        # 3. Client sends final ACK to server
        packet = create_packet(sequence_number, ack, 4, window_size, "".encode())
        client_socket.sendto(packet, serverAddress)
    else:
        raise Exception('SYN-ACK packet not received!')

    #######
    # Set timeout using measured RTT
    #######
    timeout_s = end_time - start_time
    if (timeout_s <= 100) :
        client_socket.settimeout(100)
        print("##### Timeout set to safe minimum of 100ms. RTT: " + str(round((timeout_s*1000), 2)) + "ms.")
    else:
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
    # Send metadata to server
    ########
    print("##### Preparing to send metadata")
    # Open file in binary mode and read data
    with open(filename, "rb") as file:
        file_data = file.read()  # Read the contents of the file into a byte string
        file_size = len(file_data)  # Determine size in bytes of the file

        # Split file into an array where each index contains up to packetsize (1460) bytes
        for index in range(0, file_size, packetsize):
            split_file.append(file_data[index:index + packetsize])

        no_of_packets = len(split_file)

        #######
        # Create metadata containing the filename, total number of packets and the total file size
        #######
        metadata = pack_metadata(filename, no_of_packets)
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
                raise Exception("Issue occurred when sending metadata: " + str(e))

    def stop_wait(): #Starts file transfer using Stop-and-Wait
        offset = sequence_number  # Sequence_number is not 0 because of previous messages.
        # Sequence_number is used as an offset for i to send the correct seq to server

        for i, packet_data in enumerate(split_file): #Iterate through the file and send each packet
            # packet = create_packet(i+offset, ack, flags, win, packet_data)
            packet = create_packet(i, 0, 0, window_size, packet_data)

            # Send packet and wait for ACK
            while True:
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
                    print(f"Timeout for packet with sequence number: {i}, resending")
                    # Timeout occurred, re-send packet
                    continue

    # Go-Back-N is a protocol that let us send continuous streams of packets without waiting
    # for ACK of the previous packet.
    def gbn(serverAddress): #Starts file transfer using GBN
        testcase_not_run = True

        base = 0  # Tracks the oldest sequence number of the oldest unacknowledged packet
        received_acks = [False] * no_of_packets  # List of packets that have not been acknowledged

        while base < no_of_packets - 1:
            received_all = True
            for i, ack in enumerate(received_acks):
                if ack and i >= base:
                    base = i
                elif ack == False and i >= base:
                    base = i
                    received_all = False
                    break
            scope = base + window_size - 1
            if scope >= no_of_packets:
                scope = no_of_packets - 1
            j = base
            if received_all:
                break
            while j <= scope:
                if j == 3 and testcase_not_run:
                    if testcase == "SKIP_SEQ":
                        j += 1
                        testcase_not_run = False
                    elif testcase == "DUPLICATE":
                        j -= 1
                        testcase_not_run = False

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
                    j += 1
            except socket.timeout:
                print("Timeout occurred. Resending packets... j:" +str(j))

    ##This is our newer, modified version of GBN.
    def gbnv2(serverAddress):
        testcaseNotRun = True  # Flag to indicate if the testcase has been executed or not
        base = 0  # Tracks the oldest sequence number of the oldest unacknowledged packet
        j = base
        received_acks = [False] * no_of_packets  # List of packets that have not been acknowledged

        # Continue until all packets have been acknowledged
        while base < no_of_packets:
            # Iterate over the received_acks list along with their indices
            for i, ack in enumerate(received_acks):
                # Check if the packet is acknowledged and its index is greater than or equal to the base
                if ack and i >= base:
                    base = i  # Update the base to the current acknowledged packet index

                # If the packet is not acknowledged and its index is greater than or equal to the base
                elif not ack and i >= base:
                    base = i  # Update the base to the current unacknowledged packet index
                    break  # Exit the loop since the next packets are not acknowledged yet

            # Set the scope of the current window
            base = j
            scope = base + window_size - 1

            # Adjust the scope if it exceeds the total number of packets
            if scope >= no_of_packets:
                scope = no_of_packets - 1

            # Send packets within the window
            while j <= scope:
                # Check if a specific testcase should be executed
                if j == 3 and testcaseNotRun:
                    # If the testcase is to skip a sequence
                    if testcase == "SKIP_SEQ":
                        j += 1
                        testcaseNotRun = False

                    # If the testcase is to duplicate a packet
                    elif testcase == "DUPLICATE":
                        j -= 1
                        testcaseNotRun = False

                # Get the data for the current packet
                data = split_file[j]

                # Mark the next expected acknowledgment as not received
                try:
                    received_acks[j + 1] = False
                except:
                    pass

                # Create the packet to be sent
                packet = create_packet(j, 0, 0, window_size, data)

                # Send the packet to the receiver
                client_socket.sendto(packet, serverAddress)
                j += 1

            try:
                # Receive ACKs for the sent packets
                j = base
                while j <= scope:
                    response, null = client_socket.recvfrom(1472)
                    seq, ack, flags, win = parse_header(response)

                    # Check if the response is an ACK and matches the expected sequence number
                    if flags == 4 and ack >= base and seq == j:
                        # Mark all packets up to the received ACK as acknowledged
                        for k in range(base, ack + 1):
                            received_acks[ack] = True

                        base = ack + 1

                        # If all packets have been acknowledged, exit the loop
                        if base == no_of_packets:
                            break
                    else:
                        print(f"Did not receive ACK for packet {j}. Resending packet...")

                        # Resend the packet that didn't receive an ACK
                        packet = create_packet(j, 0, 0, window_size, data)
                        client_socket.sendto(packet, serverAddress)
                        break

                    j += 1
            # if anything else happens that is unexpected this line of code will be executed
            except socket.timeout:
                print("Timeout occurred. Resending packets... j:" + str(j))
                j = base

    def sr(): #Starts file transfer using SR
        testcase_not_run = True

        # Dette er bare for at dere skjønner men base er basically i = 0 som var i SR
        base = 0  # Tracks the oldest sequence number of the oldest unacknowledged packet
        received_acks = [False] * no_of_packets  # List of packets that have not been acknowledged

        while base < no_of_packets - 1:
            received_all = True
            for i, ack in enumerate(received_acks):
                if ack and i >= base:
                    base = i
                elif ack == False and i >= base:
                    base = i
                    received_all = False
                    break
            scope = base + window_size - 1
            if scope >= no_of_packets:
                scope = no_of_packets - 1
            j = base
            if received_all:
                break
            while j <= scope:
                if j == 3 and testcase_not_run:
                    if testcase == "SKIP_SEQ":
                        j += 1
                        testcase_not_run = False
                    elif testcase == "DUPLICATE":
                        j -= 1
                        testcase_not_run = False
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
                    j += 1
            except socket.timeout:
                print("Timeout occurred. Resending packets... j:" +str(j))


    ##This is our newer, modified version of SR.
    def srv2():
        # Flag to indicate if the testcase has been executed or not
        testcaseNotRun = True

        # Tracks the oldest sequence number of the oldest unacknowledged packet
        base = 0

        # List of packets that have not been acknowledged
        received_acks = [False] * no_of_packets

        # Continue until all packets have been acknowledged
        while base < no_of_packets:
            # Send packets within the window
            j = base

            # Calculate the scope of the current window
            scope = min(base + window_size, no_of_packets) - 1

            # Track the last packet sent within the window
            last_sent_packet = base - 1

            # Iterate through the packets within the window
            while j <= scope:
                # Check if a specific testcase should be executed
                if j == 3 and testcaseNotRun:
                    # If the testcase is to skip a sequence
                    if testcase == "SKIP_SEQ":
                        j += 1
                        testcaseNotRun = False
                        continue

                    # If the testcase is to duplicate a packet
                    elif testcase == "DUPLICATE":
                        packet = create_packet(j - 1, 0, 0, window_size, split_file[j - 1])
                        client_socket.sendto(packet, serverAddress)
                        print("Sent duplicate packet:", j - 1)
                        j += 1
                        testcaseNotRun = False
                        continue

                # Get the data for the current packet
                data = split_file[j]

                # If the packet has not been acknowledged, send it
                if received_acks[j] == False:
                    packet = create_packet(j, 0, 0, window_size, data)
                    client_socket.sendto(packet, serverAddress)
                    last_sent_packet = j  # Update the last sent packet within the window
                    j += 1
                else:
                    scope += 1  # Expand the scope of the window
                    j += 1

            # Receive ACKs within the window
            for k in range(base, scope + 1):
                try:
                    # Receive response from the server
                    response, null = client_socket.recvfrom(1472)

                    # Parse the header of the response
                    seq, ack, flags, win = parse_header(response)

                    # Check if the response is an ACK for an unacknowledged packet
                    if flags == 4 and base <= ack < no_of_packets and not received_acks[ack]:
                        received_acks[ack] = True

                        # If the ACK is for the base packet
                        if ack == base:
                            # Move the base to the next unacknowledged packet
                            while base < no_of_packets and received_acks[base]:
                                base += 1

                            # If all packets have been acknowledged, exit the loop
                            if base == no_of_packets:
                                break

                            # If there is a gap in the received ACKs, exit the loop
                            elif base == scope + 1:
                                break
                        else:
                            print("ACK has been skipped. Resending packet...")

                            # Resend packets from the next one after the last sent packet within the window
                            for resend_packet in range(last_sent_packet + 1, ack + 1):
                                # Resend packet
                                packet = create_packet(resend_packet, 0, 0, window_size, split_file[resend_packet])
                                client_socket.sendto(packet, serverAddress)
                                print("Sent packet:", resend_packet)

                            break  # Stop iterating over received ACKs if there is a gap

                except socket.timeout:
                    print(f"Timeout occurred. Resending packet {base}...")
                    break


    # Sender sends a packet and waits to receive ack. After receiving ack, a new packet will be sendt.
    # If no ack received, it waits for timeout, and tries to send the packet again.

    # SR: Du får ack etter hver eneste pakke.

    # Send file with chosen reliability protocol
    transfer_start_time = time.time() # Saves start time so that the total duration and throughput can be calculated
    if reliability == "SAW":
        stop_wait()  # Send packet using Stop-And-Wait
    elif reliability == "GBN":
        gbn(serverAddress)  # Send packet using Go-Back-N protocol
    elif reliability == "GBNV2":
        gbnv2(serverAddress)
    elif reliability == "SR":
        sr()  # Send packet using Selective Repeat protocol
    elif reliability == "SRV2":
        srv2()
    transferEndTime = time.time()
    transfer_time = transferEndTime - transfer_start_time #Calculates duration of file transfer

    file.close()

    print("##### Transfer complete.")
    print("##Note: 1000 bits = 1Kb - 1000 bytes = 1KB")
    print("## Total time: " + str(round(transfer_time, 2)) + ". Size of file transferred: " + str(
        file_size / 1000) + "KB.")
    file_size = file_size * 8  ## Converting file_size to bits
    throughput = (file_size / transfer_time) / 1000_000  ##Calculating Mbps
    print("## Throughput: " + str(round(throughput, 2)) + "Mbps")

    # ------- two way handshake ---------
    # ends the connection with a two-way handshake
    # Create FIN packet and sends to server
    sequence_number = 0
    acknowledgment_number = seq  # Server acknowledges that packet with sequence_nr is received
    flags = 2  # FIN flags

    packet = create_packet(sequence_number, acknowledgment_number, flags, window_size, "".encode())
    client_socket.sendto(packet, serverAddress)

    # Receive response and parse header
    response, null = client_socket.recvfrom(1472)
    seq, ack, flags, win = parse_header(response)

    # Recives ACK for the FIN and closes connection
    if flags == 6:  # If flags == FIN-ACK
        client_socket.close()
        print("##### Connection closed")

    else:
        print("Error closing connection from client")

    # ----- slutten på two way handshake -------


# Packs file metadata. Used in client to tell server how to name the file and how big it is
def pack_metadata(filename, no_of_packets):
    return (str(filename) + ":" + str(no_of_packets)).encode()


# Unpacks metadata. Used by server to check for errors (comparing expected and actual filesize), name file and how many packets to expect
def unpack_metadata(metadata):
    metadata = metadata.decode()
    array = metadata.split(":")
    filename = array[0]
    no_of_packets = array[1]
    return filename, no_of_packets


# Functions for input validation
def check_file(filename):  # Checks if the file exists in the server's system
    if filename == None:
        return None
    if os.path.isfile(filename):
        return filename
    else:
        raise argparse.ArgumentTypeError("Could not find file with path " + str(filename))


def check_ip(val):  # Checks input of -i flag
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
def check_reliability(val):
    val = val.upper()
    if val is None:
        return None
    elif val == "SAW" or val == "STOP_AND_WAIT":
        return "SAW"
    elif val == "GBN":
        return "GBN"
    elif val == "SR":
        return "SR"
    elif val == "SRV2":
        return "SRV2"
    elif val == "GBNV2":
        return "GBNV2"
    else:
        raise Exception(
            "Could not parse -r reliability input. Expected: \"SAW\", \"STOP_AND_WAIT\", \"GBN\" or \"SR\". Actual: " + str(val))


# Check test case type from command line argument
def check_test_case(val):
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
def check_window(val):
    val = int(val)
    if not (1 <= val <= 15):
        raise Exception("Invalid window_size. Expected value between 1 and 15. Actual: " + str(val))
    else:
        return val



parser = argparse.ArgumentParser(description="positional arguments", epilog="end of help")  # Initialises argsparse parser
# Arguments
parser.add_argument('-s', '--server', action='store_true', default=False, help="Start in server mode. Default.")
parser.add_argument('-c', '--client', action='store_true', default=False, help="Start in client mode")
parser.add_argument('-i', '--ip', type=check_ip, default="127.0.0.1", help="IP to connect to")
parser.add_argument('-p', '--port', type=checkPort, default="8088", help="Bind to provided port. Default 8088")
parser.add_argument('-f', '--file', type=check_file, default=None, help="Path to file")
parser.add_argument('-r', '--reliable', type=check_reliability, default="SAW", help="Choose method for transfer (SAW, GBN or SR)")
parser.add_argument('-t', '--testcase', type=check_test_case, default=None, help="Simulate loss of packets to test error handling in the code.")
parser.add_argument('-w', '--windowsize', type=check_window, default=5, help="Set the window size for GBN and SR.")
args = parser.parse_args()  # Parses arguments provided by user

if args.server:
    print("##### Starting in server mode")
    print("## Protocol: " + str(args.reliable) + " | Testcase: " + str(args.testcase) + " | Window: " + str(args.windowsize))
    server(args.ip, args.port, args.reliable, args.testcase, args.windowsize)
elif args.client:
    print("##### Starting in client mode")
    print("## Protocol: " + str(args.reliable) + " | File: " + str(args.file) + " | Testcase: " + str(args.testcase) + " | Window: " + str(args.windowsize))
    client(args.ip, args.port, args.file, args.reliable, args.testcase, args.windowsize)
else:
    print("##### Could not start the program.")

