import socket
import os

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
    sniffer.settimeout(5)
    print(sniffer.recvfrom(65565))

    # if using Windows, turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == "__main__":
    main()
