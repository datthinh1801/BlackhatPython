import argparse
import socket
import subprocess
import shlex
import sys
import threading


def execute(cmd: str) -> bytes:
    cmd = cmd.strip()
    if not cmd:
        return None
    # stderr = subprocess.STDOUT
    # also capture stderr to stdout
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output


def parse_arguments():
    parser = argparse.ArgumentParser(description="Netcat by @datthinh1801")
    parser.add_argument(
        "-l",
        "--listen",
        help="enable listening mode",
        action="store_true",
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="specify the host to listen on", type=str
    )
    parser.add_argument(
        "-p",
        "--port",
        help="port number to listen on or connect to",
        type=int,
        required=True,
    )
    parser.add_argument("--shell", help="open a command shell", action="store_true")
    parser.add_argument(
        "-e", "--execute", help="specify the command to execute", type=str
    )
    parser.add_argument("-t", "--target", help="specify the target IP", type=str)
    parser.add_argument("-u", "--upload", help="upload a file", type=str)
    return parser.parse_args()


class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.buffer_size = 4096
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.listen:
            self._listen()
        else:
            self._send()

    def _send(self):
        self.socket.connect((self.args.target, self.args.port))
        # if the client has to send data to the server first
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ""
                # if the other end of the socket is closed,
                # data would be an empty string.
                # therefore, this 'while' condition would handle that case.
                while recv_len > 0:
                    data = self.socket.recv(self.buffer_size)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < self.buffer_size:
                        break

                if response:
                    print(response)
                    self.buffer = input("> ")
                    # the listener expects '\n' indicating the end of client's input
                    self.buffer += "\n"
                    self.socket.send(self.buffer.encode())
        except KeyboardInterrupt:
            print("[*] Exiting...")
            self.socket.close()
            sys.exit()

    def _listen(self):
        self.socket.bind((self.args.host, self.args.port))
        self.socket.listen(5)

        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(target=self._handle, args=(client_socket,))
            client_thread.start()

    def _handle(self, client_socket: socket.socket):
        """
        Handle the client connection.

        Args:
            client_socket (socket): The client socket.
        """
        if self.args.execute:
            # execute a command specified by the client
            output = execute(self.args.execute)
            client_socket.send(output)
        elif self.args.upload:
            # receive a file from the client
            file_buffer = b""
            while True:
                data = client_socket.recv(self.buffer_size)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, "wb") as f:
                f.write(file_buffer)
            message = f"Saved the file to {self.args.upload}"
            client_socket.send(message.encode())
        elif self.args.shell:
            # open an interactive shell
            while True:
                try:
                    client_socket.send(b"$ ")
                    cmd_buffer = ""
                    while "\n" not in cmd_buffer:
                        cmd_buffer += client_socket.recv(self.buffer_size).decode()
                    output = execute(cmd_buffer)
                    client_socket.send(output)
                except KeyboardInterrupt:
                    print("[*] Exiting...")
                    self.socket.close()
                    sys.exit()


if __name__ == "__main__":
    args = parse_arguments()
    netcat = NetCat(args)
    netcat.run()
