import socket
import threading
import argparse
import sys
import re
import time
import datetime
import struct
import os


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
    while True:
        msg, client_address = server_socket.recvfrom(1024)
        msg = msg.decode()
        if "PING" in msg:
            print(f"Received PING from client", end="\r")
            server_socket.sendto("ACK:PING".encode(), client_address)
        elif "FILE" in msg:
            print("preparing to receive file from client " + str(client_address))
            # Storing indexes in a set as these are more efficient for this use case
            received_chunks = set()
            ##Mangler kode for å motta filnavn
            filename = ""
            ########
            # Last index that was received from client. Starts at -1 as the first index is supposed to be 0
            lastIndex = -1
            while True:
                # Server first receives the index
                index, addr = server_socket.recvfrom(1024)
                index = index.decode()
                print(str(index))
                # If index is "END", the client is done transferring the file
                if "END" in index:
                    break
                # Server then receives the payload
                payload, addr = server_socket.recvfrom(1024)
                payload = payload.decode()
                print(payload)
                print(f"Recieving chunk " + str(index), end="\r")

                if lastIndex == int(index) - 1:
                    # Append incoming data to file variable
                    file += str(payload)
                    print("mottatt" + str(index))
                    ack = "ACK:" + str(index)
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

        # Open the file , evt use wb to ensure that the data is sent as bytes
        with open(filename) as f:
            while True:
                data, serverAddress = server_socket.recvfrom(1024)
                if not data:
                    break
                f.write(data)  # Write the received data to the file

                if reliability:
                    # send acknowledgment to client
                    msg = "ACK".encode()
                    server_socket.sendto(msg, serverAddress)

        server_socket.close()

        return 0


def client(ip, port, filename, reliability, testcase):
    # creating the socket and server address touple
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverAddress = (ip, port)

    # Ping server and set client timeout
    client_socket.settimeout(500)
    done = False
    timeout = None
    while not done:
        print(f"Pinging server", end="\r")
        startTime = time.time()
        client_socket.sendto("PING".encode(), serverAddress)
        response, null = client_socket.recvfrom(1024)
        if "ACK:PING" in response.decode():
            timeout = 4 * (time.time() - startTime)

            # Setting timeout. If RTT is lower than 10ms, timeout is set to a safe low value of 50ms
            # Otherwise, it's set to 4*RTT
            if timeout < 0.01:
                print("RTT is lower than 10ms. Setting client timeout to 50ms. Actual RTT: " + str(
                    round(timeout * 1000, 2)) + "ms")
                client_socket.settimeout(50)
            else:
                print("RTT: " + str(round(timeout * 1000, 2)) + "ms. Setting client timeout to " + str(
                    round(4 * timeout * 1000, 2)))
                client_socket.settimeout(4 * timeout)
            done = True
        else:
            print("else. Done: " + str(done))

    # Start file transfer
    done = False
    file = open("index.html", "rb")
    index = 0
    client_socket.sendto("FILE".encode(), serverAddress)
    while not done:
        print(f"Sending chunk " + str(index), end="\r")
        data = file.read(950)  # Transfer 950 bytes at a time, reserving 74 out of 1024 bytes for index
        if not data:
            done = True
            break

        print("INDEX")
        print(index)
        print("DATA")
        print(data)
        # chunk = (index, data)
        # chunk = bytes(str(chunk), "utf-8")
        # client_socket.sendto(chunk, serverAddress)
        # print(chunk.decode("utf-8"))

        # SEND INDEX
        client_socket.sendto(str(index).encode(), serverAddress)
        client_socket.sendto(str(data).encode(), serverAddress)

        response, null = client_socket.recvfrom(1024)
        expectedResponse = "ACK:" + str(index)
        if not response.decode() == expectedResponse:
            print("send ACK REQ på nytt")

    # Sends "END" when file transfer is done
    client_socket.sendto("END".encode(), serverAddress)
    print("Sent file index.html to " + str(serverAddress))

    return 0


# def wait
# def stop

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
            "Could not parse -r reliability input. Expected: \"SAW\", \"STOP_AND_WAIT\", \"GBN\" or \"SR\". Actual: " + str(
                val))


parser = argparse.ArgumentParser(description="positional arguments",
                                 epilog="end of help")  # Initialises argsparse parser

# Arguments
parser.add_argument('-s', '--server', action='store_true', default=False, help="Start in server mode. Default.")
parser.add_argument('-c', '--client', action='store_true', default=False, help="Start in client mode")
parser.add_argument('-i', '--ip', type=checkIP, default="127.0.0.1")
parser.add_argument('-p', '--port', type=checkPort, default="8088", help="Bind to provided port. Default 8088")
# parser.add_argument('-f', '--file', type=XXX, default=None, help="Path to file to transfer")
parser.add_argument('-r', '--reliable', type=checkReliability, default=None, help="XXXX")
parser.add_argument('-t', '--testcase', type=None, default=None, help="XXXX")
args = parser.parse_args()  # Parses arguments provided by user

if args.server:
    print("starting server")
    server(args.ip, args.port, None, None)
elif args.client:
    print("client starting")
    client(args.ip, args.port, None, None, None)
else:
    print("Could not start")
