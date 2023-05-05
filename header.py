'''
    #Utility functions: 1) to create a packet of 1472 bytes with header (12 bytes) (sequence number, acknowledgement number,
    #flags and receiver window) and applicaton data (1460 bytes), and 2) to parse
    # the extracted header from the application data.

'''

from struct import *


# I integer (unsigned long) = 4bytes and H (unsigned short integer 2 bytes)
# see the struct official page for more info

header_format = '!IIHH'

#print the header size: total = 12


def create_packet(seq, ack, flags, win, data):
    #creates a packet with header information and application data
    #the input arguments are sequence number, acknowledgment number
    #flags (we only use 4 bits),  receiver window and application data
    #struct.pack returns a bytes object containing the header values
    #packed according to the header_format !IIHH
    header = pack (header_format, seq, ack, flags, win)

    #once we create a header, we add the application data to create a packet
    #of 1472 bytes
    packet = header + data
    return packet


def parse_header(header):
    #taks a header of 12 bytes as an argument,
    #unpacks the value based on the specified header_format
    #and return a tuple with the values
    header = header[:12]
    header_from_msg = unpack(header_format, header)
    #parse_flags(flags)
    return header_from_msg


def parse_flags(flags):
    #we only parse the first 3 fields because we're not
    #using rst in our implementation
    syn = flags & (1 << 3)
    ack = flags & (1 << 2)
    fin = flags & (1 << 1)
    return syn, ack, fin




