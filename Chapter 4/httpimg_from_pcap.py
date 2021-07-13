import collections
import os
import re
import sys
import zlib

from scapy.all import TCP, rdpcap

OUTDIR = os.getcwd()
PCAPS = os.getcwd()

Response = collections.namedtuple("Response", ["header", "payload"])


def get_header(payload):
    """Get the headers of a HTTP response."""
    try:
        header_raw = payload[: payload.index(b"\r\n\r\n") + 2]
    except ValueError:
        sys.stdout.write("-")
        sys.stdout.flush()
        return None

    # create a dict of all headers
    header = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", header_raw.decode()))

    # find the Content-Type header
    if "Content-Type" not in header:
        return None
    return header


def extract_content(response, content_name="image"):
    """Get the content of a HTTP response."""
    content, content_type = None, None

    # if the content is an image
    if content_name in response.header["Content-Type"]:
        content_type = response.header["Content-Type"].split("/")[1]
        content = response.payload[response.payload.index(b"\r\n\r\n") + 4:]

        # extract the image
        if "Content-Encoding" in response.header:
            if response.header["Content-Encoding"] == "gzip":
                content = zlib.decompress(response.payload, zlib.MAX_WBITS | 32)
            elif response.header["Content-Encoding"] == "deflate":
                content = zlib.decompress(response.payload)
    return content, content_name


class Recapper:
    def __init__(self, fname):
        pcap = rdpcap(fname)  # return a packet list
        # create a dictionary of TCP sessions from the packet list
        self.sessions = pcap.sessions()
        self.responses = list()

    def get_responses(self):
        for session in self.sessions:
            payload = b""
            for packet in self.sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        # aggregate all HTTP messages
                        payload += bytes(packet[TCP].payload)
                except IndexError:
                    sys.stdout.write("x")
                    sys.stdout.flush()

            if payload:
                header = get_header(payload)
                if header is None:
                    continue
                self.responses.append(Response(header, payload))

    def write(self, content_name):
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response, content_name)
            if content and content_type:
                fname = os.path.join(OUTDIR, f"ex_{i}.{content_type}")
                print(f"Writing {fname}...")
                with open(fname, "wb") as f:
                    f.write(content)


if __name__ == "__main__":
    pcap = os.path.join(PCAPS, "pcap.pcap")
    recapper = Recapper(pcap)
    recapper.get_responses()
    recapper.write("image")
