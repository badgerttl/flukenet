#!/usr/bin/env python3
"""
FlukeNet — UNIVERSAL
- Platform: Linux/macOS/Windows
- Docker: Works without privileged (using macvlan)
- Interfaces: 100% agnostic
"""

from flask import Flask, render_template, request, jsonify, send_file
import csv
import time
import threading
import os
import platform
import socket

# Scapy with fallback
try:
    from scapy.all import sniff, Ether, Raw, get_if_list, get_if_hwaddr, get_if_addr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

app = Flask(__name__, template_folder='templates')

PORT = 5002
if os.environ.get('DOCKER'):
    CSV_FILE = "/data/switch_port.csv"
    DATA_DIR = "/data"
else:
    DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
    CSV_FILE = os.path.join(DATA_DIR, 'switch_port.csv')
    os.makedirs(DATA_DIR, exist_ok=True)
sniffer_thread = None
sniffing = False
current_switch = {}
lock = threading.Lock()

# =============================
# PLATFORM-AGNOSTIC INTERFACES
# =============================
def get_interfaces():
    ifaces = []

    if SCAPY_AVAILABLE:
        for iface in get_if_list():
            if 'lo' in iface:
                continue
            try:
                ip = get_if_addr(iface) or "—"
                mac = get_if_hwaddr(iface) or "—"
                ifaces.append({"name": iface, "ip": ip, "mac": mac})
            except:
                ifaces.append({"name": iface, "ip": "—", "mac": "—"})

    if not ifaces:
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if 'lo' in iface:
                    continue
                addrs = netifaces.ifaddresses(iface)
                ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', "—")
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', "—")
                ifaces.append({"name": iface, "ip": ip, "mac": mac})
        except ImportError:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for iface in ['eth0', 'en0', 'enp0s3', 'wlan0', 'Wi-Fi', 'Ethernet']:
                try:
                    ip = socket.gethostbyname(iface)
                    mac = "—"
                    ifaces.append({"name": iface, "ip": ip, "mac": mac})
                except:
                    ifaces.append({"name": iface, "ip": "—", "mac": "—"})

    return ifaces or [{"name": "No interfaces detected", "ip": "—", "mac": "—"}]

# =============================
# TLV PARSER
# =============================
def parse_tlv(raw):
    i = 0
    chassis = port = sys_name = None
    info = {"TTL": "", "Port Desc": "", "Sys Desc": "", "Caps": "", "Mgmt IP": "", "VLAN": "", "MAC/PHY": ""}
    while i < len(raw) - 1:
        hdr = int.from_bytes(raw[i:i+2], 'big')
        typ = (hdr >> 9) & 0x7F
        leng = hdr & 0x1FF
        i += 2
        if i + leng > len(raw): break
        val = raw[i:i+leng]
        i += leng

        if typ == 1 and leng >= 2 and val[0] == 4:
            chassis = ':'.join(f'{b:02x}' for b in val[1:])
        elif typ == 2 and leng >= 2:
            port = val[1:].decode('utf-8', errors='ignore').strip()
        elif typ == 5:
            sys_name = val.decode('utf-8', errors='ignore').strip()
        elif typ == 3:
            info["TTL"] = str(int.from_bytes(val, 'big'))
        elif typ == 4:
            info["Port Desc"] = val.decode('utf-8', errors='ignore').strip()
        elif typ == 6:
            info["Sys Desc"] = val.decode('utf-8', errors='ignore').strip()
        elif typ == 7 and leng >= 4:
            # System Capabilities TLV: 2 bytes system capabilities, 2 bytes enabled capabilities
            sys_caps = int.from_bytes(val[0:2], 'big')
            enabled_caps = int.from_bytes(val[2:4], 'big')
            cap_names = []
            for bit, name in [(1,"Other"), (2,"Repeater"), (4,"Bridge"), (8,"WLAN"),
                             (16,"Router"), (32,"Phone"), (64,"DOCSIS"), (128,"Station")]:
                if sys_caps & bit:
                    if enabled_caps & bit:
                        cap_names.append(f"{name}*")
                    else:
                        cap_names.append(name)
            info["Caps"] = ", ".join(cap_names) if cap_names else "—"
        elif typ == 8 and leng >= 5:
            # Management Address TLV structure (IEEE 802.1AB):
            # Byte 0: Management Address String Length (includes subtype byte, so actual address length = this - 1)
            # Byte 1: Management Address Subtype (1=IPv4, 2=IPv6, 6=MAC, etc.)
            # Bytes 2 to (1+addr_len): The actual management address
            # Byte (2+addr_len): Interface Numbering Subtype
            # Bytes after: Interface Number (variable length, typically 4 bytes for ifIndex)
            # Optional: OID Length and OID
            mgmt_addr_str_len = val[0]
            if mgmt_addr_str_len > 0 and len(val) >= mgmt_addr_str_len + 1:
                addr_subtype = val[1]
                addr_len = mgmt_addr_str_len - 1  # Subtract 1 for the subtype byte
                if addr_len > 0 and len(val) >= 2 + addr_len:
                    addr_bytes = val[2:2+addr_len]
                    mgmt_addr_str = ""
                    if addr_subtype == 1 and addr_len == 4:  # IPv4
                        mgmt_addr_str = '.'.join(str(b) for b in addr_bytes)
                    elif addr_subtype == 2 and addr_len == 16:  # IPv6
                        # Format IPv6 as groups of 4 hex digits
                        ipv6_parts = [f'{int.from_bytes(addr_bytes[i:i+2], "big"):04x}' for i in range(0, 16, 2)]
                        mgmt_addr_str = ':'.join(ipv6_parts)
                    elif addr_subtype == 6 and addr_len == 6:  # MAC
                        mgmt_addr_str = ':'.join(f'{b:02x}' for b in addr_bytes)
                    else:
                        # Unknown subtype, show as hex
                        mgmt_addr_str = ':'.join(f'{b:02x}' for b in addr_bytes)
                    
                    # Extract interface number if present
                    if len(val) >= 2 + addr_len + 1:
                        iface_num_subtype = val[2 + addr_len]
                        # Interface number is typically 4 bytes for ifIndex (subtype 1 or 2)
                        if len(val) >= 2 + addr_len + 5:
                            iface_num = int.from_bytes(val[2 + addr_len + 1:2 + addr_len + 5], 'big')
                            if iface_num > 0:
                                info["Mgmt IP"] = f"{mgmt_addr_str} (ifIndex {iface_num})"
                            else:
                                info["Mgmt IP"] = mgmt_addr_str
                        else:
                            info["Mgmt IP"] = mgmt_addr_str
                    else:
                        info["Mgmt IP"] = mgmt_addr_str
        elif typ == 127 and leng >= 6:  # Organizationally Specific TLV
            oui_bytes = val[0:3]
            oui = int.from_bytes(oui_bytes, 'big')
            if len(val) >= 4:
                subtype = val[3]
                # IEEE 802.1 OUI (00:80:C2) - Port VLAN ID
                # OUI bytes: 0x00, 0x80, 0xC2 = 0x0080C2
                if oui == 0x0080C2 and subtype == 1 and len(val) >= 6:
                    # Port VLAN ID (PVID): VLAN ID is in bytes 4-5, upper 4 bits are reserved
                    vlan_id = int.from_bytes(val[4:6], 'big') & 0x0FFF
                    if vlan_id > 0:  # Only set if valid (0 is typically not used)
                        info["VLAN"] = str(vlan_id)
                # IEEE 802.3 OUI (00:12:0F) - MAC/PHY Configuration/Status
                # OUI bytes: 0x00, 0x12, 0x0F = 0x00120F (or 0x120F, same value)
                elif (oui == 0x00120F or oui == 0x120F) and subtype == 1 and len(val) >= 9:
                    # MAC/PHY Configuration/Status TLV structure:
                    # Byte 4: Auto-negotiation support/status (bit 0: supported, bit 1: enabled)
                    # Byte 5: Auto-negotiation capabilities
                    # Bytes 6-7: Operational MAU type
                    auto_neg = val[4] if len(val) > 4 else 0
                    auto_neg_caps = val[5] if len(val) > 5 else 0
                    mau_type = int.from_bytes(val[6:8], 'big') if len(val) >= 8 else 0
                    
                    mac_phy_parts = []
                    if auto_neg & 0x01:
                        mac_phy_parts.append("Auto-neg supported")
                    if auto_neg & 0x02:
                        mac_phy_parts.append("Auto-neg enabled")
                    if mau_type > 0:
                        # Common MAU types (simplified)
                        mau_names = {
                            0x0001: "10BASE5", 0x0002: "FOIRL", 0x0003: "10BASE2",
                            0x0004: "10BASE-T", 0x0005: "10BASE-FP", 0x0006: "10BASE-FB",
                            0x0007: "10BASE-FL", 0x0008: "10BROAD36", 0x0009: "10BASE-T HD",
                            0x000A: "10BASE-T FD", 0x000B: "10BASE-FL HD", 0x000C: "10BASE-FL FD",
                            0x000D: "100BASE-T4", 0x000E: "100BASE-X HD", 0x000F: "100BASE-X FD",
                            0x0010: "100BASE-T2 HD", 0x0011: "100BASE-T2 FD", 0x0012: "1000BASE-X HD",
                            0x0013: "1000BASE-X FD", 0x0014: "1000BASE-T HD", 0x0015: "1000BASE-T FD",
                            0x0016: "10GBASE-X", 0x0017: "10GBASE-W", 0x0018: "10GBASE-R"
                        }
                        mau_name = mau_names.get(mau_type, f"MAU-{mau_type:04X}")
                        mac_phy_parts.append(mau_name)
                    if mac_phy_parts:
                        info["MAC/PHY"] = ", ".join(mac_phy_parts)
    return chassis, port, sys_name, info

# =============================
# SNIFFER
# =============================
def sniffer(iface):
    global current_switch, sniffing
    switch_mac = None
    seen_keys = set()

    def handler(pkt):
        nonlocal switch_mac, seen_keys
        if not sniffing: return
        if pkt[Ether].type != 0x88cc or Raw not in pkt: return

        src_mac = pkt[Ether].src
        raw = pkt[Raw].load
        chassis, port, sys_name, info = parse_tlv(raw)
        if not chassis or not port or not sys_name: return
        if ".local" in sys_name.lower(): return

        key = (chassis, port)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        if switch_mac is None or src_mac != switch_mac:
            switch_mac = src_mac
            seen_keys.clear()
            with lock:
                current_switch.update({
                    "mac": switch_mac, "chassis": chassis, "port": port, "name": sys_name,
                    "ttl": info["TTL"], "desc": info["Port Desc"], "sys_desc": info["Sys Desc"],
                    "caps": info["Caps"], "mgmt_ip": info["Mgmt IP"], "vlan": info["VLAN"], 
                    "mac_phy": info["MAC/PHY"], "timestamp": timestamp
                })

        if key in seen_keys: return
        seen_keys.add(key)

        row = [timestamp, switch_mac, chassis, port, info["TTL"],
               sys_name, info["Port Desc"], info["Sys Desc"], info["Caps"], info["Mgmt IP"], info["VLAN"], info["MAC/PHY"]]
        file_exists = os.path.isfile(CSV_FILE) and os.path.getsize(CSV_FILE) > 0
        with open(CSV_FILE, 'a', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            if not file_exists:
                w.writerow(["Timestamp","Switch MAC","Chassis ID","Port ID","TTL","System Name","Port Desc","Sys Desc","Caps","Mgmt IP","VLAN","MAC/PHY"])
            w.writerow(row)

    try:
        sniff(iface=iface, filter="ether proto 0x88CC", prn=handler, store=False)
    except Exception as e:
        print(f"[!] Sniff error: {e}")

# =============================
# ROUTES
# =============================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/interfaces')
def api_interfaces():
    ifaces = get_interfaces()
    html = '<option value="">Select Interface...</option>'
    for i in ifaces:
        html += f'<option value="{i["name"]}">{i["name"]} ({i["ip"]})</option>'
    return html

@app.route('/api/interface-status/<iface>')
def api_interface_status(iface):
    status = '—'
    try:
        import subprocess
        sys_type = platform.system()
        if sys_type == 'Linux':
            result = subprocess.run(['ip', 'link', 'show', iface], 
                                  capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'state UP' in line or ('UP' in line and 'state' in line):
                        status = 'UP'
                        break
                    elif 'state DOWN' in line or ('DOWN' in line and 'state' in line):
                        status = 'DOWN'
                        break
        elif sys_type == 'Darwin':
            result = subprocess.run(['ifconfig', iface], 
                                  capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'status: active' in line.lower():
                        status = 'UP'
                        break
                    elif 'status: inactive' in line.lower():
                        status = 'DOWN'
                        break
    except:
        pass
    return jsonify({"status": status})

@app.route('/api/local/<iface>')
def api_local(iface):
    ip = '—'
    netmask = '—'
    broadcast = '—'
    mac = '—'
    mtu = '—'
    status = '—'
    
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        
        if netifaces.AF_INET in addrs:
            ipv4 = addrs[netifaces.AF_INET][0]
            ip = ipv4.get('addr', '—')
            netmask = ipv4.get('netmask', '—')
            broadcast = ipv4.get('broadcast', '—')
        
        if netifaces.AF_LINK in addrs:
            mac = addrs[netifaces.AF_LINK][0].get('addr', '—')
        
        try:
            import subprocess
            sys_type = platform.system()
            if sys_type == 'Linux':
                result = subprocess.run(['ip', 'link', 'show', iface], 
                                      capture_output=True, text=True, timeout=1)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'mtu' in line.lower():
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part.lower() == 'mtu':
                                    if i + 1 < len(parts):
                                        mtu = parts[i + 1]
                                        break
                        if 'state UP' in line or (status == '—' and 'UP' in line and 'state' in line):
                            status = 'UP'
                        elif 'state DOWN' in line or (status == '—' and 'DOWN' in line and 'state' in line):
                            status = 'DOWN'
            elif sys_type == 'Darwin':
                result = subprocess.run(['ifconfig', iface], 
                                      capture_output=True, text=True, timeout=1)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'mtu' in line.lower():
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part.lower() == 'mtu':
                                    if i + 1 < len(parts):
                                        mtu = parts[i + 1]
                                        break
                        if 'status: active' in line.lower() or 'up' in line.lower():
                            status = 'UP'
                        elif 'status: inactive' in line.lower():
                            status = 'DOWN'
        except:
            pass
            
    except ImportError:
        try:
            ip = get_if_addr(iface) or '—'
            mac = get_if_hwaddr(iface) or '—'
        except:
            pass
    
    network = '—'
    if ip != '—' and netmask != '—' and ip != '0.0.0.0':
        try:
            import ipaddress
            net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            network = str(net.network_address)
        except:
            pass
    
    return f"""
    <div class="space-y-3 text-left">
      <p class="text-xl font-bold text-center mb-3" style="color: var(--fluke-amber);">{iface}</p>
      <div class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
        <div><span style="color: var(--fluke-text-muted);">IP Address:</span></div>
        <div class="font-mono" style="color: var(--fluke-amber-light);">{ip}</div>
        
        <div><span style="color: var(--fluke-text-muted);">MAC Address:</span></div>
        <div class="font-mono text-xs" style="color: var(--fluke-amber-light);">{mac}</div>
        
        <div><span style="color: var(--fluke-text-muted);">Netmask:</span></div>
        <div class="font-mono" style="color: var(--fluke-text);">{netmask}</div>
        
        <div><span style="color: var(--fluke-text-muted);">Network:</span></div>
        <div class="font-mono" style="color: var(--fluke-text);">{network}</div>
        
        <div><span style="color: var(--fluke-text-muted);">Broadcast:</span></div>
        <div class="font-mono" style="color: var(--fluke-text);">{broadcast}</div>
        
        <div><span style="color: var(--fluke-text-muted);">MTU:</span></div>
        <div style="color: var(--fluke-text);">{mtu}</div>
        
        <div><span style="color: var(--fluke-text-muted);">Status:</span></div>
        <div style="color: {'var(--fluke-amber)' if status == 'UP' else 'var(--fluke-text-muted)' if status == 'DOWN' else 'var(--fluke-text)'};">{status}</div>
      </div>
    </div>
    """

@app.route('/api/switch')
def api_switch():
    with lock:
        if not current_switch:
            if sniffing:
                return '<p class="animate-pulse" style="color: var(--fluke-amber);">Sniffing LLDP packets...</p>'
            else:
                return '<p style="color: var(--fluke-text-muted);">Ready. Click Start to begin.</p>'
        s = current_switch
        return f"""
        <div class="space-y-4 text-left">
          <div class="flex justify-between items-center pb-2 border-b" style="border-color: var(--fluke-border);">
            <span class="text-xl font-bold" style="color: var(--fluke-amber);">{s['name']}</span>
            <span class="text-xs" style="color: var(--fluke-text-muted);">{s['timestamp']}</span>
          </div>
          <div class="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
            <div><span style="color: var(--fluke-text-muted);">Port:</span> <span class="font-mono" style="color: var(--fluke-amber-light);">{s['port']}</span></div>
            <div><span style="color: var(--fluke-text-muted);">Chassis:</span> <span class="font-mono text-xs" style="color: var(--fluke-amber-light);">{s['chassis']}</span></div>
            <div><span style="color: var(--fluke-text-muted);">MAC:</span> <span class="font-mono text-xs" style="color: var(--fluke-amber-light);">{s['mac']}</span></div>
            <div><span style="color: var(--fluke-text-muted);">VLAN:</span> <span class="font-mono" style="color: var(--fluke-amber-light);">{s.get('vlan', '—') or '—'}</span></div>
            <div><span style="color: var(--fluke-text-muted);">TTL:</span> <span style="color: var(--fluke-text);">{s['ttl']}s</span></div>
            <div><span style="color: var(--fluke-text-muted);">Desc:</span> <span style="color: var(--fluke-text);">{s['desc'] or '—'}</span></div>
            <div><span style="color: var(--fluke-text-muted);">Sys Desc:</span> <span class="text-xs" style="color: var(--fluke-text);">{(s['sys_desc'] or '')[:60]}{'...' if len(s['sys_desc'] or '') > 60 else ''}</span></div>
            <div><span style="color: var(--fluke-text-muted);">Caps:</span> <span class="text-xs" style="color: var(--fluke-text);">{s.get('caps', '—') or '—'}</span></div>
            <div><span style="color: var(--fluke-text-muted);">Mgmt IP:</span> <span class="font-mono" style="color: var(--fluke-amber-light);">{s.get('mgmt_ip', '—') or '—'}</span></div>
            <div><span style="color: var(--fluke-text-muted);">MAC/PHY:</span> <span class="text-xs" style="color: var(--fluke-text);">{s.get('mac_phy', '—') or '—'}</span></div>
          </div>
        </div>
        """

@app.route('/api/history')
def api_history():
    if not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0:
        return '<tr><td colspan="10" class="text-center py-8" style="color: var(--fluke-text-muted);">No switches detected yet</td></tr>'

    rows = []
    try:
        with open(CSV_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(f"""
                <tr class="border-t transition" style="border-color: var(--fluke-border);">
                  <td class="py-3 px-2 font-mono text-xs" style="color: var(--fluke-text-muted);">{row['Timestamp']}</td>
                  <td class="py-3 px-2 font-medium" style="color: var(--fluke-amber);">{row['System Name']}</td>
                  <td class="py-3 px-2 font-mono" style="color: var(--fluke-amber-light);">{row['Port ID']}</td>
                  <td class="py-3 px-2 font-mono text-xs" style="color: var(--fluke-text);">{row['Switch MAC']}</td>
                  <td class="py-3 px-2 font-mono text-xs" style="color: var(--fluke-text);">{row['Chassis ID']}</td>
                  <td class="py-3 px-2 font-mono text-xs" style="color: var(--fluke-amber-light);">{row.get('VLAN', '—') or '—'}</td>
                  <td class="py-3 px-2 text-xs" style="color: var(--fluke-text);">{row['Port Desc'] or '—'}</td>
                  <td class="py-3 px-2 text-xs" style="color: var(--fluke-text);">{row.get('Caps', '—') or '—'}</td>
                  <td class="py-3 px-2 font-mono text-xs" style="color: var(--fluke-amber-light);">{row.get('Mgmt IP', '—') or '—'}</td>
                  <td class="py-3 px-2 text-xs" style="color: var(--fluke-text);">{row.get('MAC/PHY', '—') or '—'}</td>
                </tr>
                """)
    except Exception as e:
        print(f"[!] CSV read error: {e}")
        return '<tr><td colspan="10" class="text-center py-8" style="color: #c85a5a;">Error reading log</td></tr>'

    return ''.join(reversed(rows))

@app.route('/api/start', methods=['POST'])
def api_start():
    global sniffer_thread, sniffing
    data = request.get_json(force=True)
    iface = data.get('interface')
    if not iface:
        return jsonify({"status": "error", "message": "No interface"}), 400
    if sniffer_thread and sniffer_thread.is_alive():
        return jsonify({"status": "error", "message": "Running"}), 400

    sniffing = True
    sniffer_thread = threading.Thread(target=sniffer, args=(iface,), daemon=True)
    sniffer_thread.start()
    return jsonify({"status": "success"})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    global sniffing, sniffer_thread
    sniffing = False
    if sniffer_thread and sniffer_thread.is_alive():
        sniffer_thread.join(timeout=2)
    sniffer_thread = None
    return jsonify({"status": "success"})

@app.route('/api/reset-sniffing', methods=['POST'])
def api_reset_sniffing():
    global sniffing, sniffer_thread, current_switch
    sniffing = False
    if sniffer_thread and sniffer_thread.is_alive():
        sniffer_thread.join(timeout=2)
    sniffer_thread = None
    current_switch = {}
    return jsonify({"status": "success"})

@app.route('/api/reset-log', methods=['POST'])
def api_reset_log():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)
    open(CSV_FILE, 'w').close()
    return jsonify({"status": "success"})

@app.route('/download')
def download():
    if os.path.exists(CSV_FILE) and os.path.getsize(CSV_FILE) > 0:
        return send_file(CSV_FILE, as_attachment=True, download_name="lldp_log.csv")
    return "No data", 404

if __name__ == '__main__':
    if not os.path.exists(CSV_FILE):
        open(CSV_FILE, 'w').close()
    print(f"FlukeNet → http://localhost:{PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)