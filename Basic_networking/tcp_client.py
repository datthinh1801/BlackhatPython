from colorama import Fore, Style
import socket

target_host = "127.0.0.1"
target_port = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_host, target_port))

s.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
resp = s.recv(4096)

print(Fore.GREEN + resp.decode() + Style.RESET_ALL)
s.close()
