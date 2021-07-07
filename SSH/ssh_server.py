import os
import paramiko
import socket
import sys
import threading

CWS = os.path.dirname(os.path.realpath(__file__))
HOSTKEY = paramiko.RSAKey(filename=os.path.join(CWS, "test_rsa.key"))


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if username == "tim" and password == "sekret":
            return paramiko.AUTH_SUCCESSFUL


if __name__ == "__main__":
    server_ip = "127.0.0.1"
    ssh_port = 2222
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((server_ip, ssh_port))
        sock.listen(100)
        print("[+] Listening for connection...")
        client, addr = sock.accept()
    except Exception as e:
        print(f"[-] Listen failed: {e}")
        sys.exit(1)
    else:
        print(f"[+] Got a connection from {client, addr}.")

    bhSession = paramiko.Transport(client)
    bhSession.add_server_key(HOSTKEY)
    server = Server()
    bhSession.start_server(server=server)

    chan = bhSession.accept(20)
    if chan is None:
        print("*** No channel. ***")
        sys.exit(1)

    print("[+] Authenticated!")
    print(chan.recv(1024))
    chan.send("Welcome to black hat SSH!")
    try:
        while True:
            command = input("Enter command: ")
            if command != "exit":
                chan.send(command)
                print(chan.recv(8192).decode())
            else:
                chan.send("exit")
                print("exiting")
                bhSession.close()
                break
    except KeyboardInterrupt:
        bhSession.close()
