# Python ARP Spoofer (Man-in-the-Middle Tool)

A custom-built network security tool written in Python using the **Scapy** library. This tool performs an **ARP Spoofing / ARP Poisoning** attack, allowing the attacker to intercept traffic between a specific target (Victim) and a Gateway (Router).

This project was developed as part of a cybersecurity lab to demonstrate Man-in-the-Middle (MitM) vulnerabilities in local networks.

## 🚀 Features
- **MAC Address Resolution:** Automatically identifies the hardware address of the target.
- **ARP Poisoning:** Sends forged ARP responses to trick the victim into mapping the Gateway's IP to the Attacker's MAC address.
- **Stealth Restoration:** Automatically restores the victim's ARP table to its original state when the script is stopped (Ctrl+C), preventing permanent network disruption.
- **Traffic Forwarding:** Works in conjunction with Linux IP forwarding to maintain the victim's connection.

## 🛠️ Prerequisites

To run this tool, you need:
* **OS:** Linux (Kali Linux recommended).
* **Language:** Python 3.
* **Libraries:** Scapy (`pip install scapy`).
* **Privileges:** Root / Sudo access (required to send raw packets).

## 🧪 Lab Environment Setup

This tool was designed and tested in a virtualized **VirtualBox** environment.

**1. The Network:**
* **Type:** VirtualBox Internal Network (Name: `ARP_Lab`)
* **Gateway (Fake):** `192.168.1.1` (No physical machine, logical mapping only)

**2. The Machines:**
| Role | OS | IP Address | MAC Address |
| :--- | :--- | :--- | :--- |
| **Attacker** | Kali Linux | `192.168.1.10` | *Changes per VM* |
| **Victim** | Ubuntu | `192.168.1.20` | *Changes per VM* |

---

## 💻 How to Use

### Step 1: Prepare the Attacker (Kali)
Before running the script, you must enable **IP Forwarding** so the victim's packets pass through your machine instead of being dropped.

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

### Step 2: Run the Tool
Clone the repository and run the script with `sudo`.

sudo python3 arp_spoof.py -t [TARGET_IP] -g [GATEWAY_IP]

Example (For this Lab): sudo python3 arp_spoof.py -t 192.168.1.20 -g 192.168.1.1
You should see output indicating that packets are being sent

### Verification & Cache flushing
To prove the attack works, or to reset the lab for a fresh test, follow these steps on the Victim Machine (Ubuntu).

1. Verify the Attack (Is it poisoned?)
Run the following command on the Victim to see the ARP table: ip neigh

Success Criteria:
    Look at the MAC address for the Gateway (192.168.1.1).
    Look at the MAC address for the Attacker (192.168.1.10).
    If they are identical, the ARP cache is poisoned, and the attack is successful.

2. Flush the ARP Cache (Reset)
If you need to clear the victim's memory to test the script again from scratch:
sudo ip neigh flush all