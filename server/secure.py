import http.server
import ssl
import socketserver
import threading
import socket

# --- CONFIGURATION ---
SERVER_IP = "192.168.1.30"  # <--- MAKE SURE THIS MATCHES YOUR SERVER VM IP
# ---------------------

def run_http_redirect():
    """
    Listens on Port 80 (HTTP).
    Redirects ALL traffic to HTTPS.
    """
    class RedirectHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            # 301 means "Moved Permanently" -> Forces browser to go to Secure Site
            self.send_response(301)
            new_url = f"https://{SERVER_IP}{self.path}"
            self.send_header('Location', new_url)
            self.end_headers()
            print(f"[HTTP] Redirecting client to {new_url}")

        # Silence logs to keep terminal clean
        def log_message(self, format, *args):
            return

    # Allow reusing the port to prevent "Address already in use" errors
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("", 80), RedirectHandler)
    print(f"[*] HTTP Server running on Port 80 (Redirects to HTTPS)")
    httpd.serve_forever()

def run_https_server():
    """
    Listens on Port 443 (HTTPS).
    Serves the index.html file securely.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("", 443), http.server.SimpleHTTPRequestHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"[*] HTTPS Server running on Port 443 (SECURE)")
    httpd.serve_forever()

if __name__ == "__main__":
    # Run both servers at the same time
    t1 = threading.Thread(target=run_http_redirect)
    t2 = threading.Thread(target=run_https_server)
    
    t1.start()
    t2.start()
