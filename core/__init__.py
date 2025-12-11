import threading
import os

# Global State Dictionary
STATUS = {
    "state": "IDLE",
    "mode": "NONE",
    "target": "192.168.1.20",
    "gateway": "192.168.1.1", 
    "interface": "eth0",
    "packets": 0,
    "target_mac": "N/A",
    "logs": ["[SYSTEM] Ready."],
    "intercepted_data": [],
    "dns_domain": "",
    "dns_ip": ""
}

STOP_EVENT = threading.Event()
SSL_STRIP_PORT = 10000 
CAPTURE_DIR = "captured_pages"

if not os.path.exists(CAPTURE_DIR):
    os.makedirs(CAPTURE_DIR)