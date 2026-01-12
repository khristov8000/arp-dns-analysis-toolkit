import threading
import os
import shutil

# Global State Dictionary to track application status and data
STATUS = {
    "state": "IDLE",
    "mode": "NONE",
    "active_tab": "dns",
    "last_stop_time": 0,    # Timestamp of last stop action to filter ghost logs

    "targets": [],          # List of target IPs provided by the user
    "active_targets": [],   # Resolved {ip, mac} dictionaries for active attacks
    
    "gateway": "192.168.1.1", 
    "interface": "eth0",
    "packets": 0,
    
    # Volatile buffers for the UI (cleared on request)
    "logs": ["[SYSTEM] Ready."],
    "intercepted_data": [],
    
    # Persistent buffers for export (retained until restart)
    "all_logs": ["[SYSTEM] Ready."], 
    "all_intercepted_data": [],
    
    "dns_domain": "",
    "dns_ip": ""
}

STOP_EVENT = threading.Event()
SSL_STRIP_PORT = 10000 
CAPTURE_DIR = "captured_pages"

# Initialize capture directory and clean up old session files
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