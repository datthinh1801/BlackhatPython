import sys
import socket
import threading
import string

# filter printable character from bytes
# if a character is imprintable, represent it as a dot (.)
HEX_FILTER = "".join([(len(repr(chr(i))) == 3) and chr(i) or "." for i in range(256)])
# the above comprehension can interpreted as follows:
# HEX_FILTER = list()
# for i in range(256):
#     if len(repr(chr(i))) == 3:
#         HEX_FILTER.append(chr(i))
#     else:
#         HEX_FILTER.append(".")


def hexdump(src, length=16, show=True):
    """Hexdump a string or a byte string like the xxd tool does."""
    if isinstance(src, bytes):
        src = src.decode()

    results = list()
    # extract every 16 bytes and hexdump them
    for i in range(0, len(src), length):
        word = str(src[i : i + length])
        hexa = " ".join([f"{ord(c):02X}" for c in word])
        # translate the word using HEX_FILTER table.
        # this method takes ordinal value of each character, maps it to the table HEX_FILTER,
        # and replaces it with the corresponding value
        printable = word.translate(HEX_FILTER)
        hexwidth = length * 3
        results.append(f"{i:04x} {hexa:<{hexwidth}} {printable}")

    if show:
        for line in results:
            print(line)
    else:
        return results


def receive_from(connection: socket.socket):
    """Receive data from the specified socket."""
    buffer = b""
    connection.timeout(5)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer


def request_handler(buffer):
    """Perform packet modifications."""
    return buffer


def response_handler(buffer):
    """Perform packet modifications."""
    return buffer


def proxy_hander(client_socket, remote_host, remote_port, receive_first):
    """
    Perform the proxy functionalities.

    This assumes that a localhost initiates a connection to this proxy.
    Then, this proxy has to connect to the remote host.
    """
    # connect to the remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    remote_buffer = b""
    # check if we have to receive data from remote host first
    # e.g. FTP servers send a banner to clients first
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print(f"[<==] Sending {len(remote_buffer)} bytes to localhost.")
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print(f"[==>] Received {len(remote_buffer)} bytes from localhost.")
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print(f"[<==] Sent to localhost.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print(f"[*] No more data. Closing connections.")
            break


if __name__ == "__main__":
    hexdump("hello world!\nMy name is Thinh!")
