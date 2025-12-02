# ARP MITM Lab Architecture and Technical Deep Dive

This document details the configuration, network topology, and technical mechanism used in the ARP Poisoning Man-in-the-Middle (MiTM) lab environment.

## 1\. Network Topology and Isolation

The lab is hosted entirely within Oracle VirtualBox using a **3-Tier topology** to simulate a local area network segment under attack.

### Network Configuration Details

- **Isolation Method:** **Internal Network (ARP_Lab)**
  - This setting creates a virtual, isolated switch. All VMs on this network can only communicate with each other, ensuring the penetration test remains ethical and does not affect the host computer's external network.
- **Packet Visibility:** The Attacker VM's network adapter (eth0) is set to **Promiscuous Mode: Allow All**.
  - This allows the Kali machine to bypass standard network filtering and capture packets not explicitly addressed to its MAC address, which is crucial for intercepting traffic.
- **Network Addressing:** All machines are assigned static IP addresses from the reserved private range 192.168.1.0/24.

## 2\. Machine Roles and Configurations

| **Machine** | **Role** | **Operating System** | **Network Card (Lab)** | **IP Address** | **Key Configuration** |
| --- | --- | --- | --- | --- | --- |
| **Kali Attacker** | Man-in-the-Middle | Kali Linux | eth0 | 192.168.1.10 | IP Forwarding Enabled, Custom Python Tool Host. |
| --- | --- | --- | --- | --- | --- |
| **Ubuntu Victim** | Client / Target | Ubuntu Desktop | enp0s3 | 192.168.1.20 | Browser used to generate target traffic (HTTP). |
| --- | --- | --- | --- | --- | --- |
| **Ubuntu Server** | Data Host / Gateway Target | Ubuntu Server | enp0s3 | 192.168.1.30 | Runs python3 -m http.server 80 to simulate an intranet web server. |
| --- | --- | --- | --- | --- | --- |

## 3\. Technical Mechanism: The Double-Sided Poison

The attack exploits the **Address Resolution Protocol (ARP)**, which is fundamentally untrustworthy as it lacks authentication.

### The Attack Flow

The Attacker (1.10) sits between the Victim (1.20) and the Server (1.30). The goal is to deceive both machines:

- **Poison Victim (1.20):** The Attacker sends continuous, forged ARP Reply packets to the Victim saying:_"Hey 1.20, I am the Server (1.30), and my MAC address is_ **_08:00:27:AA:BB:CC_** _(Attacker's MAC)."_
  - **Effect:** The Victim updates its ARP cache to route all traffic destined for the Server's IP (1.30) to the **Attacker's MAC address**.
- **Poison Server (1.30):** The Attacker sends forged ARP Reply packets to the Server saying:_"Hey 1.30, I am the Victim (1.20), and my MAC address is_ **_08:00:27:AA:BB:CC_** _(Attacker's MAC)."_
  - **Effect:** The Server updates its ARP cache to route all traffic destined for the Victim's IP (1.20) to the **Attacker's MAC address**.

### Result: Interception

Because traffic must now flow through the Attacker in both directions, the Attacker can inspect the plain HTTP packets using Wireshark, capturing sensitive data before forwarding it on to the correct destination.

## 4\. Tool Implementation Details (Python/Flask)

### Custom ARP Tool

- **Library:** **Scapy** is used to craft and send raw layer-2 (Ethernet) packets (scapy.ARP).
- **Spoof Function:** The core spoof(target_ip, spoof_ip) function uses op=2 (ARP Reply) and sets the psrc (source IP) to the machine it is impersonating.
- **Restoration:** The restore() function retrieves the legitimate MAC addresses and sends corrective ARP packets (count=4) to clean the victims' caches upon exiting the script.

### Flask Dashboard

- **Background Execution:** The ARP poisoning loop is executed in a separate **Python Thread** to prevent the Flask web server from freezing.
- **Control:** A threading.Event is used for communication, allowing the web buttons to safely start and stop the persistent attack loop.
- **IP Forwarding:** The script automatically enables IP forwarding (net.ipv4.ip_forward = 1) at launch and reverts it to 0 during cleanup, ensuring the MiTM route is active only during the attack.