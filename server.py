import socket
import threading
import json

HOST = 'localhost'
PORT = 5555

clients = {}  # {client_id: socket}
payloads = {}  # {client_id: full_payload_from_client}
lock = threading.Lock()


def send_line(sock, data: dict):
    sock.sendall((json.dumps(data) + "\n").encode())


def recv_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode().strip()


def handle_client(sock, addr):
    client_id = ""
    try:
        client_id = sock.recv(10).decode().strip()
        print(f"🔗 {client_id} connected from {addr}")

        # Receive the encrypted payload and signature
        data = recv_line(sock)
        payload = json.loads(data)

        with lock:
            clients[client_id] = sock
            payloads[client_id] = payload

        # Wait until all three payloads are collected
        while True:
            with lock:
                if len(payloads) == 3:
                    break

        # Send the two other clients' payloads to this client
        with lock:
            for peer_id, peer_payload in payloads.items():
                if peer_id != client_id:
                    send_line(sock, {
                        "id": peer_id,
                        "payloads": peer_payload["payloads"],
                        "sig": peer_payload["sig"]
                    })

        print(f"✅ Payload relay completed for {client_id}")

        # Relay encrypted messages
        while True:
            data = sock.recv(4096)
            if not data:
                break
            with lock:
                for other_id, other_sock in clients.items():
                    if other_id != client_id:
                        try:
                            other_sock.send(data)
                        except:
                            continue

    except Exception as e:
        print(f"⚠️ Error handling {client_id or addr}: {e}")
    finally:
        with lock:
            if client_id in clients:
                del clients[client_id]
            if client_id in payloads:
                del payloads[client_id]
        sock.close()
        print(f"🔌 {client_id} disconnected")


def start_server():
    server = socket.socket()
    server.bind((HOST, PORT))
    server.listen(3)
    print(f"📡 Server listening on {HOST}:{PORT}")

    while True:
        sock, addr = server.accept()
        threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()


if __name__ == "__main__":
    start_server()
