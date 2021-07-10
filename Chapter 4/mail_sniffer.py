from scapy.all import sniff, TCP, IP


# callback function
def process_packet(packet):
    if packet[TCP].payload:
        tcp_payload = str(packet[TCP].payload)
        if "user" in tcp_payload.lower() or "pass" in tcp_payload.lower():
            print(f"[+] Destination: {packet[IP].dst}")
            print(f"[+] {tcp_payload}")


def main():
    sniff(
        filter="tcp port 110 or tcp port 25 or tcp port 143",  # wireshark style filter
        prn=process_packet,  # callback function
        store=0,  # not store the packet in memory
    )


if __name__ == "__main__":
    main()
