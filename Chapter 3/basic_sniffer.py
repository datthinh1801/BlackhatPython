import os
import socket


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

    # report sniffer info for testing
    print(sniffer)
    # sniff a packet
    raw_packet = sniffer.recvfrom(65565)[0]

    # if using Windows, turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    return raw_packet


if __name__ == "__main__":
    raw_packet = sniff(socket.gethostbyname(socket.gethostname()))
