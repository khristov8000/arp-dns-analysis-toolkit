import threading
import os
import shutil

# Global State Dictionary
STATUS = {
    "state": "IDLE",
    "mode": "NONE",
    "active_tab": "dns",
    "target": "192.168.1.20",
    "gateway": "192.168.1.1", 
    "interface": "eth0",
    "packets": 0,
    "target_mac": "N/A",
    
    # --- VIEW BUFFERS (Cleared by button) ---
    "logs": ["[SYSTEM] Ready."],
    "intercepted_data": [],
    
    # --- HISTORY BUFFERS (Permanent for Export) ---
    "all_logs": ["[SYSTEM] Ready."], 
    "all_intercepted_data": [],
    
    "dns_domain": "",
    "dns_ip": ""
}

STOP_EVENT = threading.Event()
SSL_STRIP_PORT = 10000 
CAPTURE_DIR = "captured_pages"

# Clean up captures on restart
if os.path.exists(CAPTURE_DIR):
    for filename in os.listdir(CAPTURE_DIR):
        file_path = os.path.join(CAPTURE_DIR, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"Failed to delete {file_path}. Reason: {e}")
else:
    os.makedirs(CAPTURE_DIR)