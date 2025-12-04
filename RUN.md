## 1. Environment Verification

Before starting the attack, verify that all three Virtual Machines are running and connected to the **Internal Network** (ARP_Lab).

### Network Map

* **Attacker (Kali Linux):** 192.168.1.10
* **Victim (Ubuntu Desktop):** 192.168.1.20
* **Server (Ubuntu Server):** 192.168.1.30

---

## 2. Phase 1: Prepare the Server (The Target)

*Perform these steps on the **Ubuntu Server VM**.*

1. **Open a Terminal.**

2. **Create the Secret File:**
   Run this command to create the "confidential" data we intend to steal.
   > echo "CONFIDENTIAL: The password is SuperSecret123" > index.html

3. **Start the Web Server:**
   Start a simple HTTP server on port 80.
   > sudo python3 -m http.server 80

   *Note: Keep this terminal window open. Do not close it.*

---

## 3. Phase 2: Prepare the Attacker (The MITM)

*Perform these steps on the **Kali Linux VM**.*

1. **Verify Network Configuration:**
   Ensure your network card is configured correctly.
   > ip a

   *Check:* Ensure `eth0` has the IP `192.168.1.10`.
   *If missing, run:*
   > sudo ip addr add 192.168.1.10/24 dev eth0
   
   > sudo ip link set eth0 up

2. **Start the Dashboard:**
   Navigate to your project folder and launch the application.
   > cd /home/attacker/Lab/
   > sudo python3 app.py

3. **Open the Interface:**
   Open the Web Browser in Kali and go to:
   **http://127.0.0.1:5000**

---

## 4. Phase 3: Launch the Attack

*Perform these steps on the **Kali Dashboard**.*

1. **Configure the Attack:**
   Enter the following details into the dashboard configuration panel:
   * **TARGET IP:** 192.168.1.20 (The Victim)
   * **GATEWAY IP:** 192.168.1.30 (The Server)
   * **INTERFACE:** eth0

2. **Start Sniffing (Wireshark):**
   Open a new terminal in Kali and launch Wireshark before starting the attack.
   > sudo wireshark

   * Select **eth0**.
   * In the filter bar at the top, type: **http**
   * Click the **Blue Shark Fin** to start capturing.

3. **Launch:**
   Click the **LAUNCH ATTACK** button on your dashboard.
   * *Check:* Look at the "Live Event Console". You should see green success messages indicating MAC resolution.

---

## 5. Phase 4: Generate & Intercept Traffic

*Perform these steps on the **Ubuntu Victim VM**.*

1. **Clear ARP Cache (Optional but Recommended):**
   To ensure the victim accepts the new path immediately.
   > sudo ip neigh flush all

2. **Access the Server:**
   Open Firefox and navigate to the server's URL:
   **http://192.168.1.30**

   * **Note:** If the page loads, the traffic has successfully passed through your Attacker machine.
   * **Troubleshooting:** If the page does not load, press **Ctrl + F5** to force a hard refresh.

---

## 6. Phase 5: View Stolen Data

*Return to the **Kali Linux VM**.*

1. Look at the **Wireshark** window.
2. Locate a packet labeled **HTTP/1.0 200 OK**.
3. **Right-click** the packet.
4. Select **Follow** > **HTTP Stream**.

**Result:** A window will open displaying the raw HTML code, including the text:
**CONFIDENTIAL: The password is SuperSecret123**

---

## 7. Phase 6: Cleanup

When finished with the lab:

1. Click **STOP ATTACK** on the Kali Dashboard to restore the network tables.
2. Close Wireshark (Stop capturing).
3. Press **Ctrl+C** in the Ubuntu Server terminal to stop the web server.