import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


def execute(cmd):
    """Execute a specified command."""
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(
        shlex.split(cmd), stderr=subprocess.STDOUT, shell=True
    )
    return output.decode()


class NetCat:
    def __init__(self, args):
        """Initialize a netcat-like object."""
        self.args = args
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set the following socket option to prevent "Address already in use" error
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        """Start the netcat-like object in either listening mode or sending mode based on the 'listen' argument from the CLI."""
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        """[SENDER] Send the contents of the buffer to the targeted host."""
        # connect to the targeted host (the listener)
        self.socket.connect((self.args.target, self.args.port))
        try:
            # a main loop to send and receive data to and from the listener
            while True:
                recv_len = 1
                response = ""
                while recv_len:
                    # receive data from server
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    # if this is the last data block received
                    if recv_len < 4096:
                        break
                if response:
                    print(response, end="")
                    buffer = input()
                    # add a \n delimiter for the server to properly interpret the command
                    buffer += "\n"
                    # send new data to the listener
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print("User terminated.")
            self.socket.close()
            sys.exit()

    def listen(self):
        """[LISTENER] Listening on the specified endpoint and handle incoming requests."""
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    def handle(self, client_socket):
        """[LISTENER] Handle the request from the sender, process the request, and return a result."""
        # -e, --execute
        # execute a command
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
            client_socket.close()
        # -u, --upload
        # receive a file and store it locally
        elif self.args.upload:
            file_buffer = b""
            client_socket.send(b"file contents> ")
            # read the contents of the uploaded file iteratively
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break

            # write the contents to a local file
            with open(self.args.upload, "wb") as f:
                f.write(file_buffer)

            message = f"Saved file {self.args.upload}"
            client_socket.send(message.encode())
            client_socket.close()
        # -c, --command
        # open an interactive shell
        elif self.args.command:
            while True:
                try:
                    client_socket.send(b"interactive shell> ")
                    cmd_buffer = b""
                    while "\n" not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(4096)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                except Exception as e:
                    print(f"Server killed {e}")
                    self.socket.close()
                    sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Crafted netcat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """Example:
            netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
            netcay.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt # upload file
            netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" # execute command
            echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135 # echo text to server port 135
            netcat.py -t 192.168.1.108 -p 5555 # connect to server
            """
        ),
    )

    parser.add_argument("-c", "--command", action="store_true", help="command shell")
    parser.add_argument("-e", "--execute", help="execute specified command")
    parser.add_argument("-l", "--listen", action="store_true", help="listen")
    parser.add_argument("-p", "--port", type=int, default=5555, help="specified port")
    parser.add_argument("-t", "--target", default="192.168.1.203", help="specified IP")
    parser.add_argument("-u", "--upload", help="upload file")
    args = parser.parse_args()

    nc = NetCat(args)
    nc.run()
