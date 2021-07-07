import socket
import os
import struct
import ipaddress
from ctypes import *

HOST = socket.gethostbyname(socket.gethostname())


def main():
    # Windows allows us to sniff all incoming packets regardless protocol
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    # Linux forces us to sniff ICMP packets only
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # if using Windows, turn on promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # read one packet
    print(sniffer)
    print(sniffer.recvfrom(65565))

    # if using Windows, turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


class IP_ctypes(Structure):
    """
    A class represents an IP packet.

    This class inherits the Structure class from the ctypes module.
    When creating a new object, bits from the raw packet will be mapped to _fields_.
    """

    _fields_ = [
        # 4 bit unsigned char
        ("ihl", c_ubyte, 4),
        # 4 bit unsigned char
        ("version", c_ubyte, 4),
        # 1 byte unsigned char
        ("tos", c_ubyte, 8),
        # 2 bytes unsigned short
        ("len", c_ushort, 16),
        # 2 bytes unsigned short
        ("id", c_ushort, 16),
        # 2 bytes unsigned short
        ("offset", c_ushort, 16),
        # 1 byte unsigned char
        ("ttl", c_ubyte, 8),
        # 1 byte unsigned char
        ("protocol_num", c_ubyte, 8),
        # 2 bytes unsigned short
        ("sum", c_ushort, 16),
        # 4 bytes unsigned int
        ("src", c_uint32, 32),
        # 4 bytes unsigned int
        ("dst", c_uint32, 32),
    ]

    @classmethod
    def __new__(cls, raw_packet=None):
        """Parse the raw packet to pre-defined fields."""
        return cls.from_buffer_copy(raw_packet)

    def __init__(self, raw_packet=None):
        # human readable IP addresses
        self.src_ip = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_ip = socket.inet_ntoa(struct.pack("<L", self.dst))


class IP_struct:
    """
    A class represents an IP packet using the struct module.
    """

    def __init__(self, raw_packet=None):
        # Reference: https://docs.python.org/3/library/struct.html
        header = struct.unpack("<BBHHHBBH4s4s", raw_packet)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP addresses
        self.src_ip = ipaddress.ip_address(self.src)
        self.dst_ip = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}


if __name__ == "__main__":
    main()
