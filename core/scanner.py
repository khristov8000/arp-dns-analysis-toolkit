import scapy.all as scapy
import socket
import struct
import fcntl

def get_local_ip_and_cidr(interface):
    # Retrieves local IP address using low-level socket IO calls
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface.encode('utf-8')[:15])
        )[20:24])
        return ip, "24" # Assumes standard /24 subnet for local labs
    except:
        return None, None

def scan_network(interface):
    # Performs ARP broadcast to discover active hosts on the subnet
    my_ip, cidr = get_local_ip_and_cidr(interface)
    if not my_ip:
        return []

    # Construct the CIDR range string (e.g., 192.168.1.0/24)
    subnet = ".".join(my_ip.split(".")[:3]) + ".0/" + cidr
    
    print(f"[*] Scanning {subnet} on {interface}...")
    
    # 
    # Create ARP request packet directed at the broadcast MAC address
    arp_req = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_req
    
    # Send packet and wait 2 seconds for replies
    result = scapy.srp(packet, timeout=2, verbose=False, iface=interface)[0]
    
    # Parse response packets into a structured dictionary
    hosts = []
    for sent, received in result:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": "Unknown"
        })
        
    return hosts