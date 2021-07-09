import socket
import os
import struct
import ipaddress
import sys


def sniff(host: str):
    # Windows allows us to sniff all incoming packets regardless protocol
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    # Linux forces us to sniff ICMP packets only
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # if using Windows, turn on promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # sniffing
    try:
        while True:
            raw_packet = sniffer.recvfrom(65565)[0]
            ip_header = IP(raw_packet)
            # print the detected protocol and host
            print(
                f"Protocol: {ip_header.protocol}\t{ip_header.src_ip} ==> {ip_header.dst_ip}"
            )
            print({ip_header.src})

    except KeyboardInterrupt:
        # if using Windows, turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit(0)


class IP:
    """
    A class represents an IP packet using the struct module.
    """

    def __init__(self, raw_packet):
        # Reference: https://docs.python.org/3/library/struct.html
        header = struct.unpack("<BBHHHBBH4s4s", raw_packet[:20])
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP addresses
        self.src_ip = ipaddress.ip_address(self.src)
        self.dst_ip = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print(f"No protocol for {(e, self.protocol_num)}")
            self.protocol = str(self.protocol_num)


class ICMP:
    def __init__(self, raw_packet):
        header = struct.unpack("<BBHHH", raw_packet[:8])
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = "127.0.0.1"
    sniff(host)
