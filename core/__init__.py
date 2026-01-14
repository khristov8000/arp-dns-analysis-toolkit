import threading
import os
import shutil

# --- GLOBAL CONFIGURATION ---
SSL_STRIP_PORT = 10000 
CAPTURE_DIR = "captured_pages"
STOP_EVENT = threading.Event()

# --- GLOBAL STATE DICTIONARY ---
# This is shared between Flask, Sniffer, ARP, and DNS.
STATUS = {
    "state": "IDLE",
    "mode": "NONE",
    "active_tab": "dns",
    
    # Target Configuration
    "targets": [],           # User inputs
    "active_targets": [],    # Resolved IPs/MACs
    "gateway": "192.168.1.1", 
    "interface": "eth0",
    
    # Counters & Buffers
    "packets": 0,
    
    # Volatile buffers (Cleared by 'clear_logs'/'clear_data')
    "logs": ["[SYSTEM] Ready."],
    "intercepted_data": [],
    
    # Persistent buffers (Kept for Export)
    "all_logs": ["[SYSTEM] Ready."], 
    "all_intercepted_data": [],
    
    # Attack Configs
    "dns_domain": "",
    "dns_ip": ""
}

# --- INITIALIZATION ---
# Create capture directory on startup
if not os.path.exists(CAPTURE_DIR):
    os.makedirs(CAPTURE_DIR)

# Clean up old captures on restart
for filename in os.listdir(CAPTURE_DIR):
    file_path = os.path.join(CAPTURE_DIR, filename)
    try:
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)
    except Exception as e:
        print(f"Failed to delete {file_path}: {e}")