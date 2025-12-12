import scapy.all as scapy
from app import create_app
from core import STATUS

if __name__ == '__main__':
      # Configure Scapy to allow IP address spoofing (required for ARP poisoning)
    scapy.conf.checkIPaddr = False
    
    # Initialize default network interface (user can select different one from dashboard)
    STATUS["interface"] = "eth0"
    
    # Create Flask application with all blueprints and route handlers
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=False)