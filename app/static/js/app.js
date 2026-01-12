// Global State Variables
let currentTab = 'dns';
let isRunning = false;
let scannedHosts = []; 
let lastLogCount = 0;

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Console
    const consoleDiv = document.getElementById('console-output');
    if (consoleDiv.innerHTML.trim() === "") {
        consoleDiv.innerHTML = '<div class="log-entry">[SYSTEM] Ready. Scan network to begin.</div>';
    }

    // Default to DNS tab if none active
    if (document.querySelectorAll('.tab-btn.active').length === 0) {
        switchTab('dns', false);
    }

    // Sync with server
    fetch('/update').then(r => r.json()).then(data => {
        if (data.state === "RUNNING") {
            if (data.active_tab) switchTab(data.active_tab, false);
            const inputs = document.querySelectorAll('input:not(#interface_name)');
            inputs.forEach(i => i.disabled = true);
        }
        updateDashboard();
    });
});

// LOCAL STORAGE (Simplified for Global Inputs) 
function saveState() {
    const getVal = (id) => {
        const el = document.getElementById(id);
        return el ? el.value : '';
    };

    const state = {
        tab: currentTab,
        interface: getVal('interface_name'),
        
        // WE ONLY SAVE GLOBAL TARGETS NOW
        target_ip: getVal('target_ip'),
        gateway_ip: getVal('gateway_ip'),
        
        // Specific Attack Configs
        dns_domain: getVal('dns_domain'),
        dns_redirect: getVal('dns_redirect')
    };
    localStorage.setItem('mitm_config', JSON.stringify(state));
}

function loadState() {
    const saved = localStorage.getItem('mitm_config');
    if (!saved) return; 

    try {
        const state = JSON.parse(saved);
        
        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if(el && val) el.value = val;
        };

        setVal('interface_name', state.interface);
        setVal('target_ip', state.target_ip);
        setVal('gateway_ip', state.gateway_ip);
        setVal('dns_domain', state.dns_domain);
        setVal('dns_redirect', state.dns_redirect);

        if (state.tab) switchTab(state.tab, false);

    } catch (e) {
        console.error("Failed to load state:", e);
    }
}

//CORE FUNCTIONS
function switchTab(mode, shouldSave = true) {
    currentTab = mode;
    
    const tabs = document.querySelectorAll('.tab-btn');
    const dnsContent = document.getElementById('dns-content');
    const sslContent = document.getElementById('ssl-content');
    const silentContent = document.getElementById('silent-content');

    tabs.forEach(t => t.classList.remove('active'));
    dnsContent.classList.add('hidden');
    sslContent.classList.add('hidden');
    silentContent.classList.add('hidden');

    if (mode === 'dns') {
        tabs[0].classList.add('active');
        dnsContent.classList.remove('hidden');
    } else if (mode === 'ssl') {
        tabs[1].classList.add('active');
        sslContent.classList.remove('hidden');
    } else {
        tabs[2].classList.add('active');
        silentContent.classList.remove('hidden');
    }

    // Clear all input fields when switching tabs
    if (shouldSave) {
        document.getElementById('target_ip').value = '';
        document.getElementById('gateway_ip').value = '';
        document.getElementById('dns_domain').value = '';
        document.getElementById('dns_redirect').value = '';
    }

    if (!isRunning && shouldSave) {}  // State saving disabled
}

function runNetworkScan() {
    const btn = document.getElementById('scan-btn');
    const iface = document.getElementById('interface_name').value;

    btn.innerText = "...";
    btn.disabled = true;
    btn.style.cursor = "wait";

    fetch('/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ interface: iface })
    })
    .then(r => r.json())
    .then(data => {
        btn.innerText = "SCAN";
        btn.disabled = false;
        btn.style.cursor = "pointer";

        if(data.status === "success") {
            scannedHosts = data.hosts || [];
            if (scannedHosts.length === 0) {
                alert("No hosts found."); return;
            }
            
            // Flash GLOBAL inputs
            flashInput('target_ip'); 
            flashInput('gateway_ip'); 
            flashInput('dns_redirect');
            
            console.log("Scan complete. Hosts cached.");
        } else {
            alert("Error: " + data.message);
        }
    });
}

function toggleAttack() {
    const iface = document.getElementById('interface_name').value;
    
    const target = document.getElementById('target_ip').value;
    const gateway = document.getElementById('gateway_ip').value;
    
    let dnsDomain = "", dnsIp = "", actionStr;

    if (currentTab === 'dns') {
        actionStr = 'start_dns';
        dnsDomain = document.getElementById('dns_domain').value;
        dnsIp = document.getElementById('dns_redirect').value; 
    } else if (currentTab === 'ssl') {
        actionStr = 'start_sslstrip';
    } else {
        actionStr = 'start_silent';
    }

    if(!target) { alert("Please enter a Target IP."); return; }
    if(!gateway) { alert("Please enter a Gateway IP."); return; }
    
    const finalAction = isRunning ? 'stop' : actionStr;
    const inputs = document.querySelectorAll('input:not(#interface_name)');
    inputs.forEach(i => i.disabled = !isRunning);

    fetch('/action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ 
            action: finalAction, 
            target: target, 
            gateway: gateway, 
            interface: iface,
            dns_domain: dnsDomain,
            dns_ip: dnsIp
        })
    }).then(() => setTimeout(updateDashboard, 500));
}

// UI HELPERS 
function showDropdown(inputElement) {
    const dropdownId = 'dropdown-' + inputElement.id;
    const dropdown = document.getElementById(dropdownId);
    if(!dropdown) return;

    dropdown.innerHTML = '';
    
    // Add scanned hosts if available
    if(scannedHosts.length > 0) {
        scannedHosts.forEach(host => {
            const ip = host.ip ? host.ip : host;
            const mac = host.mac ? host.mac : 'Unknown';
            const div = document.createElement('div');
            div.className = 'dropdown-item';
            div.innerHTML = `<span>${ip}</span><span class="mac">${mac}</span>`;
            div.onmousedown = function(e) {
                e.preventDefault(); 
                inputElement.value = ip;
                dropdown.classList.remove('show');
            };
            dropdown.appendChild(div);
        });
    }
    
    // Add hardcoded Gateway IP option only for DNS tab and gateway_ip field
    if (inputElement.id === 'gateway_ip' && currentTab === 'dns') {
        // Add divider
        const divider = document.createElement('div');
        divider.style.borderTop = '1px solid #333';
        divider.style.margin = '5px 0';
        divider.style.height = '0';
        dropdown.appendChild(divider);
        
        const div = document.createElement('div');
        div.className = 'dropdown-item';
        div.innerHTML = `<span>192.168.1.1</span><span class="mac"></span>`;
        div.onmousedown = function(e) {
            e.preventDefault(); 
            inputElement.value = '192.168.1.1';
            dropdown.classList.remove('show');
        };
        dropdown.appendChild(div);
    }
    
    dropdown.classList.add('show');
}

function hideDropdown(inputElement) {
    setTimeout(() => {
        const dropdownId = 'dropdown-' + inputElement.id;
        const dropdown = document.getElementById(dropdownId);
        if(dropdown) dropdown.classList.remove('show');
    }, 200);
}

function flashInput(id) {
    const el = document.getElementById(id);
    if(el) {
        el.classList.remove('input-flash');
        void el.offsetWidth;
        el.classList.add('input-flash');
    }
}

function closeModal() { 
    document.getElementById('scan-modal').style.display = "none"; 
}

window.onclick = function(event) { 
    if (event.target == document.getElementById('scan-modal')) closeModal(); 
}

// ... (Keep existing variable declarations: currentTab, isRunning, etc.) ...

// ... (Keep existing loadState, saveState, switchTab, runNetworkScan, toggleAttack functions) ...

function updateDashboard() {
    fetch('/update').then(r => r.json()).then(data => {
        // Metrics
        const pktCount = document.getElementById('packet_count');
        const modeLabel = document.getElementById('current_mode');
        const macLabel = document.getElementById('target_mac');
        
        if(pktCount) pktCount.innerText = data.packets;
        if(modeLabel) modeLabel.innerText = data.mode;
        if(macLabel) macLabel.innerText = data.target_mac;

        // State Sync
        const wasRunning = isRunning;
        isRunning = (data.state === "RUNNING");
        if (isRunning && !wasRunning && data.active_tab) switchTab(data.active_tab, false);

        // Buttons (Visual Update)
        const btnDns = document.getElementById('launch-btn-dns');
        const btnSsl = document.getElementById('launch-btn-ssl');
        const btnSilent = document.getElementById('launch-btn-silent');
        let activeBtn = (currentTab === 'dns') ? btnDns : (currentTab === 'ssl') ? btnSsl : btnSilent;

        if (isRunning) {
            if(activeBtn) { activeBtn.innerText = "STOP ATTACK"; activeBtn.className = "btn stop"; }
            document.querySelectorAll('.tab-btn').forEach(t => t.style.pointerEvents = "none");
        } else {
            if(btnDns) { btnDns.innerText = "LAUNCH DNS ATTACK"; btnDns.className = "btn start"; }
            if(btnSsl) { btnSsl.innerText = "LAUNCH SSL STRIP"; btnSsl.className = "btn start"; }
            if(btnSilent) { btnSilent.innerText = "START MONITOR"; btnSilent.className = "btn start"; btnSilent.style.background = "#555"; }
            document.querySelectorAll('.tab-btn').forEach(t => t.style.pointerEvents = "all");
            const inputs = document.querySelectorAll('input:not(#interface_name)');
            inputs.forEach(i => i.disabled = false);
        }

        // --- SIMPLIFIED CONSOLE LOGS (3 COLORS) ---
        const consoleDiv = document.getElementById('console-output');
        if (consoleDiv && data.logs.length !== lastLogCount) {
            lastLogCount = data.logs.length;
            consoleDiv.innerHTML = "";
            
            const isEffectivelyEmpty = (data.logs.length === 0) || (data.logs.length === 1 && data.logs[0].includes("[SYSTEM] Ready."));
            if (isEffectivelyEmpty) {
                consoleDiv.innerHTML = '<div class="log-entry placeholder-entry">[SYSTEM] Ready. Scan network to begin.</div>';
            } else {
                data.logs.slice().reverse().forEach(log => {
                    const div = document.createElement('div');
                    div.className = "log-entry";
                    
                    // --- NEW 3-COLOR PALETTE ---
                    let colorStyle = "#aaaaaa"; // 1. GREY (Default / System)
                    
                    // 2. GREEN: Active, Starting, Success, Config, DNS, Proxy
                    if (log.includes("[*]") || log.includes("[+]") || log.includes("[CONFIG]") || 
                        log.includes("[DNS]") || log.includes("[PROXY]") || log.includes("[NET]") ||
                        log.includes("ATTACK ACTIVE")) {
                        colorStyle = "#4cff79"; 
                    }
                    
                    // 3. RED: Stops, Errors, Captured Data
                    else if (log.includes("[-]") || log.includes("STOPPED") || 
                             log.includes("[DATA]") || log.includes("[ALERT]") || 
                             log.includes("ERROR")) {
                        colorStyle = "#ff4f4f"; 
                    }
                    // ---------------------------
                    
                    div.style.color = colorStyle;
                    div.innerText = log;
                    consoleDiv.appendChild(div);
                });
            }
        }
        
        // --- INTERCEPTS (Keep simplified) ---
        const dataDiv = document.getElementById('data_output');
        if (dataDiv) {
            dataDiv.innerHTML = "";
            if (data.intercepted_data.length > 0) {
                data.intercepted_data.slice().reverse().forEach(item => {
                    let color = "#ff8c42"; 
                    if (item.type === "ALERT") color = "#ff4f4f"; // Red
                    if (item.type === "INFO") color = "#28a745";  // Green
                    if (item.type === "WARNING") color = "#aaaaaa"; // Grey

                    const displayTitle = item.title || "RAW DATA";

                    const div = document.createElement('div');
                    div.className = "log-entry intercept-entry";
                    div.style.borderLeft = `3px solid ${color}`;
                    div.innerHTML = `
                        <div style="font-size:11px; color:#555; display:flex; justify-content:space-between; margin-bottom: 2px;">
                            <span>[${item.time}] ${item.src} &rarr; ${item.dst}</span>
                            <a href="/view/${item.id || ''}" target="_blank" style="color:${color}; font-weight:bold; text-decoration:none;">VIEW FULL</a>
                        </div>
                        <div style="color:${color}; font-weight:bold; font-size:12px; margin-bottom:2px;">
                            [${displayTitle}]
                        </div>
                        <div style="color:#e3e3e3; font-family:monospace; word-break:break-all; font-size: 11px; white-space: pre-wrap;">${item.snippet}</div>
                    `;
                    dataDiv.appendChild(div);
                });
            } else {
                dataDiv.innerHTML = '<div class="log-entry placeholder-entry" style="opacity:0.5">Waiting for traffic...</div>';
            }
        }
    });
}

function clearConsole(target) {
    const actionType = (target === 'console-output') ? 'clear_logs' : 'clear_data';
    if(target === 'console-output') lastLogCount = -1;
    fetch('/action', {
        method: 'POST', 
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ action: actionType })
    });
}

function toggleConsole(id, btn) {
    const consoleDiv = document.getElementById(id);
    const isCollapsed = consoleDiv.classList.toggle('collapsed');
    btn.style.transform = isCollapsed ? "rotate(-90deg)" : "rotate(0deg)";
}

// Update dashboard every 1 second
setInterval(updateDashboard, 1000);
