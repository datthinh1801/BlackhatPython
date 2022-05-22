from colorama import Fore, Style
import getpass
import os
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
    return parser.parse_args()


class NetCat:
    def __init__(self, args):
        self.args = args
        self.buffer = ""
        self.buffer_size = 4096
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.listen:
            self._listen()
        else:
            self._send()

    def _send(self):
        self.socket.connect((self.args.host, self.args.port))
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

                    if recv_len == 0:
                        print(
                            Fore.RED
                            + "[*] Connection closed by the server"
                            + Style.RESET_ALL
                        )
                        self.socket.close()
                        exit()

                if response:
                    print(response, end="")
                    self.buffer = input().strip()
                    if self.buffer == "exit":
                        self.socket.close()
                        sys.exit()

                    # the listener expects '\n' indicating the end of client's input
                    self.buffer += "\n"
                    self.socket.send(self.buffer.encode())
        except KeyboardInterrupt:
            print(Fore.YELLOW + "[*] Exiting..." + Style.RESET_ALL)
            self.socket.close()
            sys.exit()

    def _listen(self):
        self.socket.bind((self.args.host, self.args.port))
        self.socket.listen(5)
        print(
            Fore.YELLOW
            + f"[*] Listening on {self.args.host}:{self.args.port}"
            + Style.RESET_ALL
        )

        while True:
            client_socket, client_addr = self.socket.accept()
            print(
                Fore.GREEN
                + f"[*] Accepted connection from {client_addr[0]}:{client_addr[1]}"
                + Style.RESET_ALL
            )
            client_thread = threading.Thread(
                target=self._handle, args=(client_socket, client_addr)
            )
            client_thread.start()

    def _handle(self, client_socket: socket.socket, client_addr: tuple):
        """
        Handle the client connection.

        Args:
            client_socket (socket): The client socket.
        """
        prompt = self._get_prompt()
        client_socket.send(prompt.encode())

        while True:
            try:
                cmd_buffer = ""
                while "\n" not in cmd_buffer:
                    buffer = client_socket.recv(self.buffer_size).decode()
                    if len(buffer) == 0:
                        print(
                            Fore.RED
                            + f"[*] Connection {client_addr[0]}:{client_addr[1]} closed by the client"
                            + Style.RESET_ALL
                        )
                        client_socket.close()
                        sys.exit()

                    cmd_buffer += buffer

                cmd_buffer = cmd_buffer.strip()
                if cmd_buffer.startswith("cd "):
                    try:
                        os.chdir(cmd_buffer[3:])
                        output = b""
                    except FileNotFoundError:
                        output = (
                            Fore.RED + "[-] Directory not found.\n" + Style.RESET_ALL
                        ).encode()
                else:
                    try:
                        output = execute(cmd_buffer)
                    except FileNotFoundError:
                        output = (
                            Fore.RED + "[-] Command not found.\n" + Style.RESET_ALL
                        ).encode()
                output += self._get_prompt().encode()
                client_socket.send(output)
            except KeyboardInterrupt:
                print("[*] Exiting...")
                self.socket.close()
                sys.exit()

    @staticmethod
    def _get_prompt():
        username = getpass.getuser()
        hostname = socket.gethostname()
        prompt = f"{username}@{hostname}:{os.getcwd()}$ "
        return Fore.GREEN + prompt + Style.RESET_ALL


if __name__ == "__main__":
    args = parse_arguments()
    netcat = NetCat(args)
    netcat.run()
