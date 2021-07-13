import socket
import os
import struct
import ipaddress
import sys


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


def sniff(host):
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

    # sniff
    try:
        while True:
            raw_packet = sniffer.recvfrom(65565)[0]
            # parse the IP packet to get IP headers
            ip_header = IP(raw_packet)
            # report IP headers
            print(
                f"{ip_header.protocol}: {ip_header.src_ip} ==> {ip_header.dst_ip}",
                end=" ",
            )
            print(f"Version: {ip_header.ver}", end=" ")
            # IHL is the number of 32-bit words of the header
            # so the number of bytes is 4 times of IHL
            print(f"HDR_length: {ip_header.ihl * 4}", end=" ")
            print(f"TTL : {ip_header.ttl}")

            # report ICMP headers
            if ip_header.protocol == "ICMP":
                # icmp packet starts at the beginning of the data section of the ip packet
                # [NOTE] IHL is the number of 32-bit words
                offset = ip_header.ihl * 4
                icmp_raw_header = raw_packet[offset: offset + 8]
                icmp_header = ICMP(icmp_raw_header)
                print(f"\tICMP -> Type: {icmp_header.type}\tCode: {icmp_header.code}")
    except KeyboardInterrupt:
        # if using Windows, turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = "127.0.0.1"
    sniff(host)
