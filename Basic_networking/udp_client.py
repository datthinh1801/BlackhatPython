import socket

target_host = "www.google.com"
target_port = 80

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s.sendto(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n", (target_host, target_port))
resp, addr = s.recvfrom(4096)

print(addr)
print(resp.decode())
s.close()
