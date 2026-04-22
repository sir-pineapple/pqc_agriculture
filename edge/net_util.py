import struct

def send_msg(sock, data):
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg(sock):
    raw_len = recv_exact(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack("!I", raw_len)[0]
    return recv_exact(sock, length)
