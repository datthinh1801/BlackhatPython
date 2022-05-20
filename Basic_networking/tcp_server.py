from colorama import Fore, Style

import socket
import threading


LIP = "127.0.0.1"
LPORT = 9999


def main():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set socket option to allow reusing a binding address
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LIP, LPORT))
    listener.listen(5)
    print(Fore.YELLOW + f"[+] Listening on {LIP}:{LPORT}" + Style.RESET_ALL)

    while True:
        try:
            client_sock, addr = listener.accept()
            print(f"[+] Received a connection from {addr[0]}:{addr[1]}.")
            client_threat = threading.Thread(target=client_handler, args=(client_sock,))
            client_threat.start()
        except KeyboardInterrupt:
            print(Fore.RED + "[-] Shutting down server..." + Style.RESET_ALL)
            break


def client_handler(client):
    with client as client_sock:
        request = client_sock.recv(1024)
        print(f"[+] Received {Fore.GREEN}{request.decode()}" + Style.RESET_ALL)
        client_sock.send(b"ACK!")


if __name__ == "__main__":
    main()
