import scapy.all as scapy
import uuid
import time
from core import STATUS, STOP_EVENT, CAPTURE_DIR
from core.utils import log_msg

# Track streams where we saw a POST header but no body yet
interesting_streams = {} 

def packet_callback(packet):
    if STOP_EVENT.is_set(): return
    
    # --- CONFIG ---
    is_silent = (STATUS.get("mode") == "SILENT")

    # --- FILTERING ---
    has_data = packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP)
    is_arp = packet.haslayer(scapy.ARP)
    
    if not (has_data or is_arp):
        return

    try:
        title = ""
        desc = ""
        type_class = "INFO"
        src_ip = ""
        dst_ip = ""
        is_alert = False

        # --- A. ARP MONITORING (Silent Mode Only) ---
        if is_arp and is_silent:
            op = packet[scapy.ARP].op
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst
            
            # Construct Data Entry for UI
            if op == 1: 
                title = "ARP REQUEST"
                desc = f"Who has {dst_ip}? Tell {src_ip}"
                type_class = "WARNING" 
            elif op == 2: 
                title = "ARP REPLY"
                desc = f"{src_ip} is at {packet[scapy.ARP].hwsrc}"
                type_class = "WARNING"
            
            is_alert = True
            # We let execution continue to the SAVE block below

        # --- B. DATA CAPTURE (TCP/HTTP) ---
        elif has_data:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            ip = packet[scapy.IP]
            tcp = packet[scapy.TCP]
            src_ip = ip.src
            dst_ip = ip.dst
            
            if tcp.sport == 10000 or tcp.dport == 10000: return 

            stream_key = (src_ip, tcp.sport)
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

        # --- COMMON SAVE LOGIC ---
        if not is_alert: return

        # Simple De-Duplication for UI cleanliness
        if len(STATUS["intercepted_data"]) > 0:
            last_entry = STATUS["intercepted_data"][-1]
            if last_entry.get("src") == src_ip and last_entry.get("title") == title and last_entry.get("snippet") == desc:
                return 

        timestamp_str = time.strftime('%H%M%S')
        clean_ip = src_ip.replace('.', '-')
        clean_title = title.replace(" ", "-").upper()
        short_uuid = str(uuid.uuid4())[:4]
        readable_id = f"{timestamp_str}_{clean_ip}_{clean_title}_{short_uuid}"
        
        # Save HTML only for Data packets
        if has_data:
            try:
                filepath = f"{CAPTURE_DIR}/{readable_id}.html"
                with open(filepath, "w", encoding="utf-8") as f: f.write(payload)
            except: pass

        data_entry = {
            "id": readable_id,
            "time": time.strftime('%H:%M:%S'),
            "src": src_ip, 
            "dst": dst_ip,
            "title": title,          
            "snippet": desc, 
            "type": type_class
        }
        
        # PUSH TO UI
        STATUS["intercepted_data"].append(data_entry)
        STATUS["all_intercepted_data"].append(data_entry)
        
        # Log High Priority Alerts to Console
        if type_class == "ALERT":
            log_msg(f"[!] {title} captured from {src_ip}")

    except Exception:
        pass

def start_sniffer():
    interface = STATUS["interface"]
    from .utils import set_promiscuous_mode 
    set_promiscuous_mode(interface, True)
    try:
        scapy.sniff(iface=interface, store=0, prn=packet_callback, 
                   stop_filter=lambda p: STOP_EVENT.is_set())
    except Exception as e:
        log_msg(f"[!] Sniffer Error: {e}")
    finally:
        set_promiscuous_mode(interface, False)