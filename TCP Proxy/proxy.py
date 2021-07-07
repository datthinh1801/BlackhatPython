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


def hexdump(src: str or bytes, length=16, show=True) -> None or str:
    """
    Hexdump a string or a byte string like the xxd tool does.

    Params:
    src:    the string source of either type str or bytes
    length: the number bytes to dump per line
    show:   hexdump the formatted data to console if True; otherwise, return that data
    """
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


def receive_from(connection: socket.socket) -> bytes:
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
        print(f"Exception on receiving data: {e}.")
    return buffer


def request_handler(buffer: bytes):
    """Perform packet modifications."""
    return buffer


def response_handler(buffer: bytes):
    """Perform packet modifications."""
    return buffer


def proxy_hander(
    client_socket: socket.socket,
    remote_host: str,
    remote_port: int,
    receive_first: bool,
) -> None:
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
        # receive data from the local host
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print(f"[==>] Received {len(remote_buffer)} bytes from localhost.")
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        # receive data from the remote host
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


def server_loop(
    local_host: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
    receive_first: bool,
) -> None:
    """
    The main loop for the server to listen to incoming connections from localhosts.

    Params:
    local_host:     the IP this proxy will listen on
    local_port:     the port this proxy will listen on
    remote_host:    the IP of the remote host that this proxy will forward local traffic to
    remote_port:    the port that the remote host is listening on
    receive_first:  True if the client has to receive first, False if the client send data first
    """
    # create a proxy server socket listening for incoming local connection
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print(f"[!] Problem on bind: {e}")
        print(f"[!] Failed to listen on {(local_host, local_port)}")
        print(f"[!] Check for other listening sockets or correct permissions.")
        sys.exit(1)

    print(f"[+] Listening on {(local_host, local_port)}")
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        # print out the local connection information
        print(f"> Received incoming connection from {addr[0]}:{addr[1]}")
        # start a thread to talk to the remote host
        proxy_thread = threading.Thread(
            target=proxy_hander,
            args=(client_socket, remote_host, remote_port, receive_first),
        )
        proxy_thread.start()


def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport] ", end="")
        print("[remotehost] [remoteport] [receivefirst]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.10.2.4 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = sys.argv[5].lower() == "true"

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)


if __name__ == "__main__":
    main()
