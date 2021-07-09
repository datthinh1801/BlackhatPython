import socket
import os
import struct
import ipaddress
import sys
import threading
import time

# targeted subnet
SUBNET = "192.168.100.0/24"
# magic string to check for
MESSAGE = "PYTHONRULES!"


class IP:
    """A class represents an IP packet parsing with the struct module."""

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
    """A class represents an ICMP packet parsing with the struct module."""

    def __init__(self, raw_packet):
        header = struct.unpack("<BBHHH", raw_packet[:8])
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


def udp_sender():
    """Send the magic message to all hosts within the SUBNET."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            # Send to port 9999 which is pretty sure closed.
            # As a result, an ICMP packet with Type 3 - Code 3 will be returned.
            sender.sendto(bytes(MESSAGE, "utf8"), (str(ip), 49151))


class Scanner:
    def __init__(self, host) -> None:
        """Initialize a socket for the scanner."""
        self.host = host
        # Windows allows us to sniff all incoming packets regardless protocol
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        # Linux forces us to sniff ICMP packets only
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # if using Windows, turn on promiscuous mode
        if os.name == "nt":
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        hosts_up = set([f"{str(self.host)} *"])
        try:
            while True:
                raw_packet = self.socket.recvfrom(65565)[0]
                # parse the IP packet to get IP headers
                ip_header = IP(raw_packet)

                # report ICMP headers
                if ip_header.protocol == "ICMP":
                    # icmp packet starts at the beginning of the data section of the ip packet
                    # [NOTE] IHL is the number of 32-bit words
                    offset = ip_header.ihl * 4
                    icmp_raw_header = raw_packet[offset : offset + 8]
                    icmp_header = ICMP(icmp_raw_header)

                    # check for DESTINATION PORT UNREACHABLE (TYPE 3 and CODE 3)
                    # [NOTE] the destined host with the port closed MAY chooses not to reply
                    # with an ICMP TYPE 3 - CODE 3 (as on Windows)
                    if icmp_header.type == 3 and icmp_header.code == 3:
                        if ipaddress.ip_address(
                            ip_header.src_ip
                        ) in ipaddress.IPv4Network(SUBNET):
                            # check our magic message
                            message_offset = len(raw_packet) - len(MESSAGE)
                            if raw_packet[message_offset:] == bytes(MESSAGE, "utf8"):
                                target = str(ip_header.src_ip)
                                if target != self.host and target not in hosts_up:
                                    hosts_up.add(str(ip_header.src_ip))
                                    print(f"Host up: {target}")
        except KeyboardInterrupt:
            # if using Windows, turn off promiscuous mode
            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

            print("User interrupted.")
            if hosts_up:
                print(f"\n\nSummary: Hosts up on {SUBNET}")
                for host in sorted(hosts_up):
                    print(host)
            sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = "127.0.0.1"
    scanner = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    scanner.sniff()
