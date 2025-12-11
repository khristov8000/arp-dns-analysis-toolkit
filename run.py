import scapy.all as scapy
from app import create_app
from core import STATUS

if __name__ == '__main__':
    # Initialize Interface Default
    scapy.conf.checkIPaddr = False
    STATUS["interface"] = "eth0" # Or detect automatically
    
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=False)