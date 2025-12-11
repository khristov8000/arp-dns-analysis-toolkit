import time
import os
import scapy.all as scapy
import subprocess  # <--- THIS WAS MISSING
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
    """ Adds/Removes iptables rule to redirect Port 80 traffic to SSL_STRIP_PORT """
    try:
        action = "-A" if enable else "-D"
        cmd = f"iptables -t nat {action} PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
        os.system(cmd)
        log_msg(f"[SYSTEM] IP Tables rule {'ADDED' if enable else 'REMOVED'} for SSL Strip.")
    except Exception as e:
        log_msg(f"[!] IP Tables Error: {e}")

def set_dns_blocking(enable):
    """ Blocks forwarded DNS traffic so ONLY our fake response gets through. """
    try:
        rule = f"iptables -{{action}} FORWARD -i {STATUS['interface']} -p udp --dport 53 -j DROP"
        if enable:
            os.system(rule.format(action="I"))
            log_msg("[SYSTEM] DNS Forwarding BLOCKED (Force Fake Response)")
        else:
            os.system(rule.format(action="D"))
            log_msg("[SYSTEM] DNS Forwarding Restored")
    except Exception as e:
        log_msg(f"[!] DNS Rules Error: {e}")

def set_promiscuous_mode(interface, enable):
    """ Enables/Disables Promiscuous Mode on the interface """
    try:
        # Check if we are root
        if os.geteuid() != 0: return 
            
        action = "promisc" if enable else "-promisc"
        
        # Try 'ip' command first (Modern Linux)
        if os.path.exists('/sbin/ip') or os.path.exists('/usr/sbin/ip') or os.path.exists('/bin/ip'): 
            subprocess.run(['ip', 'link', 'set', interface, action, 'on' if enable else 'off'], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Fallback to 'ifconfig'
        elif os.path.exists('/sbin/ifconfig'): 
            subprocess.run(['ifconfig', interface, action], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if enable:
            log_msg(f"[+] Interface {interface} set to Promiscuous Mode.")
        else:
            # log_msg(f"[-] Promiscuous Mode disabled.")
            pass

    except Exception as e:
        log_msg(f"[!] Warning: Could not set Promiscuous Mode: {e}")

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False, iface=STATUS["interface"])[0] 
        return answered_list[0][1].hwsrc if answered_list else None
    except: return None