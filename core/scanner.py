import scapy.all as scapy
import socket
import struct
import fcntl

def get_local_ip_and_cidr(interface):
    """ Detects IP and assumes /24 subnet for the interface """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface.encode('utf-8')[:15])
        )[20:24])
        return ip, "24"
    except:
        return None, None

def scan_network(interface):
    """ 
    Scans the subnet and returns a list of active hosts.
    """
    my_ip, cidr = get_local_ip_and_cidr(interface)
    if not my_ip:
        return []

    # Target the whole subnet (e.g., 192.168.1.0/24)
    subnet = ".".join(my_ip.split(".")[:3]) + ".0/" + cidr
    
    print(f"[*] Scanning {subnet} on {interface}...")
    
    # Broadcast ARP Request
    arp_req = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_req
    
    # Send & Receive (timeout=2 is usually enough for local LAN)
    result = scapy.srp(packet, timeout=2, verbose=False, iface=interface)[0]
    
    # Extract IPs and MACs
    hosts = []
    for sent, received in result:
        # We must return a Dictionary, not just the IP string
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": "Unknown"
        })
       
        
    return hosts