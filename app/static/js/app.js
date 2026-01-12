// Global state variables
let currentTab = 'dns';
let isRunning = false;
let scannedHosts = []; 
let lastLogCount = 0;
let isProcessing = false; 

document.addEventListener('DOMContentLoaded', () => {
    // Initialize console if empty
    const consoleDiv = document.getElementById('console-output');
    if (consoleDiv.innerHTML.trim() === "") {
        consoleDiv.innerHTML = '<div class="log-entry">[SYSTEM] Ready. Scan network to begin.</div>';
    }

    // Default to DNS tab
    if (document.querySelectorAll('.tab-btn.active').length === 0) {
        switchTab('dns', false);
    }

    // Sync state with server
    fetch('/update').then(r => r.json()).then(data => {
        if (data.state === "RUNNING") {
            if (data.active_tab) switchTab(data.active_tab, false);
            const inputs = document.querySelectorAll('input:not(#interface_name)');
            inputs.forEach(i => i.disabled = true);
        }
        updateDashboard();
    });
});

// UI Switching logic
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

    if (shouldSave) {
        document.getElementById('target_ip').value = '';
        document.getElementById('gateway_ip').value = '';
        document.getElementById('dns_domain').value = '';
        document.getElementById('dns_redirect').value = '';
    }
}

// Dynamic Target Fields management
let targetIndex = 1;

function addTargetField(value = '') {
    const container = document.getElementById('target-container');
    const id = `target_ip_${targetIndex++}`;

    const div = document.createElement('div');
    div.className = 'input-wrapper target-row';
    div.innerHTML = `
        <input type="text" name="target_ip" class="target-input" id="${id}" 
               value="${value}" placeholder="Another Target IP..." 
               onfocus="showDropdown(this)" onblur="hideDropdown(this)">
        <button type="button" class="btn-icon remove" onclick="removeTargetField(this)">−</button>
        <div class="custom-dropdown" id="dropdown-${id}"></div>
    `;
    container.appendChild(div);
}

function removeTargetField(btn) {
    btn.parentElement.remove();
}

// Network Action Functions
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
            
            flashInput('gateway_ip'); 
            flashInput('dns_redirect');
            
            document.querySelectorAll('.target-input').forEach(el => {
                el.classList.remove('input-flash');
                void el.offsetWidth;
                el.classList.add('input-flash');
            });
            
            console.log("Scan complete. Hosts cached.");
        } else {
            alert("Error: " + data.message);
        }
    });
}

function toggleAttack() {
    // Prevent double submissions
    if (isProcessing) return; 
    isProcessing = true;

    const iface = document.getElementById('interface_name').value;
    const gateway = document.getElementById('gateway_ip').value;
    
    const targetInputs = document.querySelectorAll('.target-input');
    const targets = Array.from(targetInputs).map(input => input.value).filter(val => val.trim() !== "");

    let dnsDomain = "", dnsIp = "", actionStr = "", btnId = ""; 

    if (currentTab === 'dns') {
        actionStr = 'start_dns';
        btnId = 'launch-btn-dns';
        dnsDomain = document.getElementById('dns_domain').value;
        dnsIp = document.getElementById('dns_redirect').value; 
    } else if (currentTab === 'ssl') {
        actionStr = 'start_sslstrip';
        btnId = 'launch-btn-ssl';
    } else {
        actionStr = 'start_silent';
        btnId = 'launch-btn-silent';
    }

    if(targets.length === 0) { 
        alert("Please enter at least one Target IP."); 
        isProcessing = false;
        return; 
    }
    if(!gateway) { 
        alert("Please enter a Gateway IP."); 
        isProcessing = false;
        return; 
    }
    
    const finalAction = isRunning ? 'stop' : actionStr;

    // Visual locking
    const activeBtn = document.getElementById(btnId);
    if(activeBtn) {
        activeBtn.disabled = true;
        activeBtn.innerText = "PROCESSING...";
        activeBtn.style.cursor = "wait";
    }
    
    const allInputs = document.querySelectorAll('input:not(#interface_name), .btn-icon');
    allInputs.forEach(i => i.disabled = true); 

    fetch('/action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ 
            action: finalAction, 
            targets: targets, 
            gateway: gateway, 
            interface: iface,
            dns_domain: dnsDomain,
            dns_ip: dnsIp
        })
    })
    .then(r => r.json())
    .then(data => {
        if(data.status === "already_running") {
            console.warn("Attack already active.");
        }
        
        // Wait for server thread settlement
        setTimeout(() => {
            updateDashboard();
            isProcessing = false;
        }, 1500);
    })
    .catch(err => {
        console.error("Action failed:", err);
        isProcessing = false; 
        if(activeBtn) {
            activeBtn.disabled = false;
            activeBtn.innerText = isRunning ? "STOP ATTACK" : "LAUNCH";
        }
    });
}

// Main Dashboard Update Loop
function updateDashboard() {
    fetch('/update').then(r => r.json()).then(data => {
        // Update metrics
        const pktCount = document.getElementById('packet_count');
        const modeLabel = document.getElementById('current_mode');
        
        if(pktCount) pktCount.innerText = data.packets;
        if(modeLabel) modeLabel.innerText = data.mode;

        // Update Status Indicator
        const statusText = document.getElementById('status-text');
        const statusDot = document.getElementById('status-dot');

        if (statusText && statusDot) {
            if (data.state === "RUNNING") {
                statusText.innerText = "ATTACK RUNNING";
                statusText.classList.remove('idle');
                statusText.classList.add('running');
                statusDot.classList.remove('idle');
                statusDot.classList.add('running');
            } else {
                statusText.innerText = "SYSTEM IDLE";
                statusText.classList.remove('running');
                statusText.classList.add('idle');
                statusDot.classList.remove('running');
                statusDot.classList.add('idle');
            }
        }

        // Sync State
        const wasRunning = isRunning;
        isRunning = (data.state === "RUNNING");
        if (isRunning && !wasRunning && data.active_tab) switchTab(data.active_tab, false);

        // Update Buttons and Inputs based on state
        const btnDns = document.getElementById('launch-btn-dns');
        const btnSsl = document.getElementById('launch-btn-ssl');
        const btnSilent = document.getElementById('launch-btn-silent');
        let activeBtn = (currentTab === 'dns') ? btnDns : (currentTab === 'ssl') ? btnSsl : btnSilent;

        if (isRunning) {
            if(activeBtn) { 
                activeBtn.innerText = "STOP ATTACK"; 
                activeBtn.className = "btn stop"; 
                activeBtn.disabled = false;         
                activeBtn.style.cursor = "pointer"; 
            }
            document.querySelectorAll('.tab-btn').forEach(t => t.style.pointerEvents = "none");
        } else {
            if(btnDns) { 
                btnDns.innerText = "LAUNCH DNS ATTACK"; 
                btnDns.className = "btn start"; 
                btnDns.disabled = false; 
                btnDns.style.cursor = "pointer";
            }
            if(btnSsl) { 
                btnSsl.innerText = "LAUNCH SSL STRIP"; 
                btnSsl.className = "btn start"; 
                btnSsl.disabled = false; 
                btnSsl.style.cursor = "pointer";
            }
            if(btnSilent) { 
                btnSilent.innerText = "START MONITOR"; 
                btnSilent.className = "btn start"; 
                btnSilent.style.background = "#555"; 
                btnSilent.disabled = false; 
                btnSilent.style.cursor = "pointer";
            }
            
            document.querySelectorAll('.tab-btn').forEach(t => t.style.pointerEvents = "all");
            const inputs = document.querySelectorAll('input:not(#interface_name)');
            inputs.forEach(i => i.disabled = false);

            // Re-enable dynamic remove buttons
            const iconButtons = document.querySelectorAll('.btn-icon');
            iconButtons.forEach(btn => {
                btn.disabled = false;
                btn.style.pointerEvents = "all";
                btn.style.cursor = "pointer";
            });
        }

        // Update Console Logs
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
                    let colorStyle = "#aaaaaa"; 
                    if (log.includes("[*]") || log.includes("[+]") || log.includes("ACTIVE")) colorStyle = "#4cff79"; 
                    else if (log.includes("[-]") || log.includes("STOPPED") || log.includes("ERROR") || log.includes("WARNING")) colorStyle = "#ff4f4f"; 
                    div.style.color = colorStyle;
                    div.innerText = log;
                    consoleDiv.appendChild(div);
                });
            }
        }
        
        // Update Intercepted Data
        const dataDiv = document.getElementById('data_output');
        if (dataDiv) {
            dataDiv.innerHTML = "";
            if (data.intercepted_data.length > 0) {
                data.intercepted_data.slice().reverse().forEach(item => {
                    let color = "#ff8c42"; 
                    if (item.type === "ALERT") color = "#ff4f4f"; 
                    if (item.type === "INFO") color = "#28a745"; 
                    if (item.type === "WARNING") color = "#aaaaaa"; 

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

// Helpers
function showDropdown(inputElement) {
    const dropdownId = 'dropdown-' + inputElement.id;
    const dropdown = document.getElementById(dropdownId);
    if(!dropdown) return;

    dropdown.innerHTML = '';
    
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
    
    // Add default gateway for DNS tab
    if (inputElement.id === 'gateway_ip' && currentTab === 'dns') {
        const divider = document.createElement('div');
        divider.style.borderTop = '1px solid #333';
        divider.style.margin = '5px 0';
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

function loadState() {
    const saved = localStorage.getItem('mitm_config');
    if (!saved) return; 

    try {
        const state = JSON.parse(saved);
        const setVal = (id, val) => { const el = document.getElementById(id); if(el) el.value = val; };

        setVal('interface_name', state.interface);
        setVal('gateway_ip', state.gateway_ip);
        
        if (Array.isArray(state.targets)) {
            if(state.targets[0]) document.getElementById('target_ip_0').value = state.targets[0];
            for(let i = 1; i < state.targets.length; i++) {
                addTargetField(state.targets[i]);
            }
        } else if (state.target_ip) {
            document.getElementById('target_ip_0').value = state.target_ip;
        }

        if (state.tab) switchTab(state.tab, false);
    } catch (e) { console.error(e); }
}

function saveState() {
    const targetInputs = document.querySelectorAll('.target-input');
    const targets = Array.from(targetInputs).map(i => i.value);

    const state = {
        tab: currentTab,
        interface: document.getElementById('interface_name').value,
        targets: targets,
        gateway_ip: document.getElementById('gateway_ip').value,
    };
    localStorage.setItem('mitm_config', JSON.stringify(state));
}

// Update dashboard every 1 second
setInterval(updateDashboard, 1000);