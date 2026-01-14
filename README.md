# ARP MITM Lab Architecture and Technical Deep Dive

This document details the configuration, network topology, and technical mechanism used in the ARP Poisoning Man-in-the-Middle (MiTM) lab environment.

## 1\. Network Topology and Isolation

The lab is hosted entirely within Oracle VirtualBox using a **3-Tier topology** to simulate a local area network segment under attack.

### Network Configuration Details

- **Isolation Method:** **Internal Network (ARP_Lab)**
  - This setting creates a virtual, isolated switch. All VMs on this network can only communicate with each other, ensuring the penetration test remains ethical and does not affect the host computer's external network.
- **Packet Visibility:** The Attacker VM's network adapter (eth0) is set to **Promiscuous Mode: Deny**.
  - This simulates a realistic **Switched Network** environment. The Attacker cannot see traffic between other machines by default. Interception is achieved solely through the ARP Poisoning mechanism implemented in the Python tool, rather than hypervisor settings.
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

## 4. Tool Implementation Details (Python/Flask)

### Overview
A comprehensive Python/Flask-based Man-in-the-Middle toolkit for network security research and penetration testing. The toolkit provides multiple attack vectors including ARP poisoning, DNS injection, and SSL stripping with a modern web-based command center.

### Architecture

#### Backend (Python/Flask)
- **Core Modules:**
  - `core/arp.py` - ARP spoofing and cache poisoning
  - `core/dns.py` - DNS spoofing and domain redirection
  - `core/sniffer.py` - Network packet capture and analysis
  - `core/ssl_strip.py` - HTTPS to HTTP downgrade attacks
  - `core/scanner.py` - Network host discovery via ARP scanning
  - `core/utils.py` - Utility functions for IP forwarding and MAC resolution

- **Threading:** Attack operations run in background threads to maintain Flask web server responsiveness
- **IP Forwarding:** Automatically enabled/disabled to ensure transparent packet routing during attacks

#### Frontend (Modular Architecture)
- **HTML Templates:** Separated into reusable components
  - `templates/index.html` - Main entry point (30 lines)
  - `templates/components/` - Modular UI sections (header, control panels, console, modals)

- **CSS:** Organized into logical modules
  - `static/css/style.css` - Main import file
  - `static/css/_globals.css` - Base styles, colors, typography
  - `static/css/_layout.css` - Grid layouts and structural elements
  - `static/css/_components.css` - Buttons, tabs, inputs, dropdowns
  - `static/css/_panels.css` - Panels, modals, console windows
  - `static/css/_utilities.css` - Animations and utility classes

- **JavaScript:** Single application file
  - `static/js/app.js` - All client-side logic (state management, UI interactions, API calls)

### Attack Modes

#### 1. DNS Mode
- **Function:** Poisons ARP caches while simultaneously hijacking DNS queries
- **Use Case:** Redirect users to fake servers, phishing attacks
- **Configuration:**
  - Target IP: Machine to intercept
  - Gateway IP: Default gateway (192.168.1.1)
  - Target Domain: Domain to redirect (e.g., www.example.com)
  - Redirect IP: Fake server IP address

#### 2. SSL Strip Mode
- **Function:** Attempts to downgrade HTTPS connections to plain HTTP
- **Use Case:** Intercept encrypted HTTPS traffic
- **Warning:** Noisy attack; modern browsers have HSTS protection
- **Configuration:**
  - Target IP: Machine to intercept
  - Gateway IP: Default gateway

#### 3. Silent Mode (Stealth Monitor)
- **Function:** Places the network interface into Promiscuous Mode to passively sniff traffic.
- **Use Case:** Undetected intelligence gathering and traffic pattern analysis.
- **Features:**
  - **No Active Injection:** Does not perform ARP poisoning or DNS spoofing.
  - **Promiscuous Sniffing:** Captures all Broadcast traffic (ARP, DHCP) and any Unicast traffic visible to the interface (simulating a compromised switch port or hub).
  - **IDS Evasion:** Completely invisible to Intrusion Detection Systems as no malicious packets are generated.

### Features

#### Network Discovery
- **Scan Function:** Discover active hosts on the network using ARP scanning
- **Display:** Dropdown menus auto-populated with discovered IPs and MAC addresses
- **Hardcoded Gateway:** 192.168.1.1 available as quick-select in DNS mode

#### Multi-Target Capabilities
- **Concurrent Poisoning:** Attack multiple victim machines simultaneously within the same session.
- **Dynamic Targeting:** Add or remove target IP addresses on the fly using the `+` and `-` controls.
- **Smart Resolution:** Automatically resolves MAC addresses for all entered targets before launching the attack.

#### Real-Time Dashboard
- **Metrics:** Live packet count, current attack mode, target MAC address
- **Console Output:** Logs all system events and attack operations
- **Sensitive Data:** Displays captured sensitive data with timestamps
- **Export Function:** Download captured data and logs

#### State Management
- **Per-Session:** Fields reset when switching attack modes or refreshing page
- **No Persistence:** No localStorage - all data cleared on page reload
- **Server Sync:** Maintains state sync with backend during active attacks

### UI/UX Design
- **Dark Theme:** Professional hacker aesthetic with high contrast
- **Color Coding:**
  - Green (#4cff79) - DNS and success states
  - Orange (#ff8c42) - SSL Strip and alerts
  - Red (#ff4f4f) - Errors and warnings
  - Blue (#1f7dff) - Primary actions and scan operations

- **Responsive Layout:**
  - Left panel: Configuration and attack controls
  - Right panel: Real-time console and data capture display
  - Collapsible sections for better space management

- **Dynamic Input Fields:**
  - **Target Management:** Intelligent input rows that allow users to stack multiple target IPs.
  - **Auto-Complete:** Dropdown menus integrate with scan results for quick target selection.
  - **Visual Feedback:** Status indicators (grey/green/red) update in real-time for all active targets.

### Dependencies
- **scapy** - Packet crafting and network manipulation
- **flask** - Web framework
- **netifaces** - Network interface management
- **python-iptables** - IP forwarding and firewall rules

### Security Considerations
 **Disclaimer:** This toolkit is for authorized security research and penetration testing only.
- **Ethical Use:** Only deploy on networks you own or have explicit authorization to test
- **Legal Compliance:** ARP poisoning and DNS spoofing may violate computer fraud laws in your jurisdiction
- **Network Impact:** Can disrupt network connectivity; handle with care in production environments

### Project Structure
```
arp-dns-analysis-toolkit/
├── app/
│   ├── templates/
│   │   ├── index.html
│   │   └── components/
│   │       ├── header.html
│   │       ├── control-panel.html
│   │       ├── dns-section.html
│   │       ├── ssl-section.html
│   │       ├── silent-section.html
│   │       ├── console-panel.html
│   │       ├── data-panel.html
│   │       └── scan-modal.html
│   ├── static/
│   │   ├── css/
│   │   │   ├── style.css
│   │   │   ├── _globals.css
│   │   │   ├── _layout.css
│   │   │   ├── _components.css
│   │   │   ├── _panels.css
│   │   │   └── _utilities.css
│   │   └── js/
│   │       └── app.js
│   └── __init__.py
├── core/
│   ├── arp.py
│   ├── dns.py
│   ├── sniffer.py
│   ├── ssl_strip.py
│   ├── scanner.py
│   ├── utils.py
│   └── __init__.py
├── run.py
├── requirements.txt
└── README.md
```

## 5.How to Run 
### Environment Verification

Before starting the attack, verify that all three Virtual Machines are running and connected to the **Internal Network** (ARP_Lab).

### Network Map

* **Attacker (Kali Linux):** 192.168.1.10
* **Victim (Ubuntu Desktop):** 192.168.1.20
* **Server (Ubuntu Server):** 192.168.1.30

---

### Phase 1: Prepare the Server (The Target)

*Perform these steps on the **Ubuntu Server VM**.*

 **For DNS Attack / Silent Mode**

1. **Open a Terminal.**

2. **Create / Place the Phishing Login Page:**
   The project ships a custom login page that is used as the phishing page. Place that file at `server/index.html` on the Ubuntu Server. Example ways to create or upload the file:

```bash
# from the project machine, write the provided HTML into the server folder
cd /home/attacker/arp-dns-analysis-toolkit/server
cat > index.html <<'EOF'
<PASTE THE PROVIDED HTML PAGE CONTENT HERE>
EOF

# or copy from your workstation to the server using scp (replace user@server)
# scp index.html user@192.168.1.30:/home/attacker/arp-dns-analysis-toolkit/server/index.html
```

3. **Start the Web Server:**
   Start a simple HTTP server on port 80.
   > sudo python3 -m http.server 80

   *Note: Keep this terminal window open. Do not close it.*

**For SSL Stripping Attack**

1. **Generate Self-Signed Certificate** (One-time setup):
   Create a self-signed SSL certificate for HTTPS interception.
   > openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 -nodes

   *Follow the prompts (you can leave most fields empty, just press Enter).*

2. **Place the Phishing Login Page:**
   Ensure the custom login page is present at `server/index.html` (see example above). If you generated certificates in the `/server` folder, the same `index.html` will be served over HTTPS by `secure.py`.

3. **Run the Secure Server Script:**
   > sudo python3 server.py

   *Note: Keep this terminal window open. Do not close it.*

---

### Phase 2: Prepare the Attacker (The MITM)

*Perform these steps on the **Kali Linux VM**.*

### Install Dependencies

Before running attacks, ensure all required packages are installed:

```bash
# Core dependencies
sudo apt-get update
sudo apt-get install -y python3-pip python3-scapy dsniff mitmproxy

# Python packages
pip3 install scapy flask netifaces python-iptables requests
```

### Attack-Specific Requirements

#### DNS Attack
- **Dependencies:** `scapy`, `flask`, `netifaces`
- **What it does:** Poisons ARP cache + hijacks DNS queries
- **Requirements:** Target and Gateway IPs, domain name to redirect

#### SSL Strip Attack  
- **Dependencies:** `scapy`, `flask`, `sslstrip`, `iptables`
- **What it does:** Downgrades HTTPS to HTTP + intercepts encrypted traffic
- **Requirements:** Target and Gateway IPs, Internet connection to handle SSL
- **Server Prep:** HTTPS server running on port 443 (see Phase 1)

#### Silent Mode
- **Dependencies:** `scapy`, `flask`, `netifaces`
- **What it does:** Monitors network "noise" (ARP Broadcasts) and unencrypted data without manipulating the ARP cache.
- **Requirements:** Network interface (eth0) only.
- **Stealth:** Zero-footprint operation; useful for mapping trust relationships (who is talking to whom) before attacking.

### Start the Dashboard

1. **Verify Network Configuration:**
   Ensure your network card is configured correctly.
   > ip a

   *Check:* Ensure `eth0` has the IP `192.168.1.10`.
   *If missing, run:*
   > sudo ip addr add 192.168.1.10/24 dev eth0
   
   > sudo ip link set eth0 up

2. **Navigate to the Project Folder:**
   > cd /home/attacker/arp-dns-analysis-toolkit

3. **Start the Flask Dashboard:**
   > sudo python3 run.py

4. **Open the Web Interface:**
   Open the Web Browser in Kali and go to:
   **http://127.0.0.1:5000**

---

### Phase 3: Scan the Network

*Perform these steps on the **Kali Dashboard**.*

1. **Click SCAN Button:**
   This will discover all active hosts on the network (192.168.1.20, 192.168.1.30, etc.)

2. **Verify Results:**
   Check the dropdown menus - they should now show discovered IPs and MAC addresses

---

### Phase 4: Configure & Launch Attack

*Perform these steps on the **Kali Dashboard**.*

**DNS Attack Configuration**

1. **Set Attack Parameters:**
   * **TARGET IP(s):** - Enter the first victim IP (e.g., 192.168.1.20).
     - *Optional:* Click the `+` button to add more target fields and enter additional victim IPs (e.g., 192.168.1.25).
   * **GATEWAY IP:** 192.168.1.1 (or 192.168.1.30 - the Server)
   * **TARGET DOMAIN:** www.example.com
   * **REDIRECT IP:** 192.168.1.30 (Your fake server)

2. **Click:** `LAUNCH DNS ATTACK`

**SSL Strip Attack Configuration**

1. **Set Attack Parameters:**
   * **TARGET IP(s):** - Enter the primary victim IP.
     - Use the `+` button to add secondary victims if needed.
   * **GATEWAY IP:** 192.168.1.30 (The Gateway / Fake server)

2. **Ensure Server is Running HTTPS:**
   Verify the Ubuntu Server has the HTTPS server running on port 443

3. **Click:** `LAUNCH SSL STRIP`

**Silent Mode Configuration**

1. **Select Interface:**
   Ensure `eth0` (or your active interface) is selected.

2. **Targeting (Optional):**
   * Unlike active attacks, Silent Mode does not require specific Target or Gateway IPs to function, as it monitors the entire segment.
   * You may leave the target fields blank or set them for your own reference.

3. **Click:** `START MONITOR`
   * The console will immediately begin logging ARP Broadcast traffic (e.g., "ARP Who has...").

---

### Phase 5: Generate & Intercept Traffic

*Perform these steps on the **Ubuntu Victim VM**.*

 **For DNS Attack**

1. **Clear ARP Cache (Optional but Recommended):**
   > sudo ip neigh flush all

2. **Access the Redirected Domain:**
   Open Firefox and try to access the domain you configured (e.g., www.example.com)
   * The traffic will be redirected to your fake server (192.168.1.30)
   * You'll see the confidential file content in your Kali console

**For SSL Strip Attack**

1. **Clear ARP Cache:**
   > sudo ip neigh flush all

2. **Access HTTP Server:**
   Open Firefox and navigate to:
   **http://192.168.1.30**
   
   * You will not get a warning that you are on a HTTP (when the attack is not launched, the server will ask you to Advance the security and send you to HTTPS)

**For Silent Mode**

1. **Observe Network "Noise":**
   * Without active poisoning, standard switches filter unicast traffic.
   * You will primarily see **Broadcast Packets** in the console (Green logs).
   * **Look for:** `[SNIFFER] ARP Who has 192.168.1.1? Tell 192.168.1.20`
   * **Analysis:** This tells you which machines are actively trying to communicate with the Gateway, helping you identify active targets for a subsequent Poisoning attack.

---

### Phase 6: Monitor Captured Data

*Return to the **Kali Dashboard**.*

1. **Check Console Output:**
   
2. **View Sensitive Data Panel:**
   - Shows captured credentials, cookies, and sensitive information
   - Displays timestamp, source, and destination of each capture

3. **Export Data:**
   - Click the **EXPORT** button to download captured data and logs

---

### Phase 7: Cleanup

When finished with the lab:

1. **Stop the Attack:**
   Click `STOP ATTACK` button on the Kali Dashboard
   * This restores ARP caches and disables IP forwarding

2. **Close Dashboard:**
   Press `Ctrl+C` in the Flask terminal

3. **Stop Server:**
   Press `Ctrl+C` in the Ubuntu Server terminal to stop the web/HTTPS server

4. **Cleanup ARP (Optional):**
   On victim machine, run:
   > sudo ip neigh flush all
