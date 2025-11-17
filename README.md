# FlukeNet

Real-time LLDP switch detection and network interface monitoring with CSV logging and universal compatibility.

## Features

- **Live LLDP Switch Detection** - Real-time detection and display of connected network switches
- **Network Interface Monitoring** - Detailed interface information including IP, MAC, netmask, broadcast, MTU, and status
- **Automatic Interface Updates** - Interface information and status refresh automatically
- **CSV History Logging** - Complete detection history with downloadable CSV export
- **Modern Fluke-Inspired UI** - Professional interface with amber color scheme
- **Platform Agnostic** - Works on Linux, macOS, and Windows
- **Auto Interface Detection** - Automatically discovers all available network interfaces

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Linux: Root or sudo access for network interface access (packet sniffing)
- macOS: May require running with sudo for packet capture
- Windows: May require running as Administrator

## Installation

### Step 1: Clone the Repository

```bash
git clone git@github.com:badgerttl/flukenet.git
cd flukenet
```

### Step 2: Install Dependencies

**Linux:**
```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev libpcap-dev
pip3 install -r requirements.txt
```

**macOS:**
```bash
pip3 install -r requirements.txt
brew install libpcap  # If needed
```

**Windows:**
```bash
pip install -r requirements.txt
```

### Step 3: Run the Application

```bash
# Linux/macOS (may require sudo for packet capture)
python3 app/flukenet.py

# Windows
python app/flukenet.py
```

The application will be available at `http://localhost:5002`

## Usage

1. Open your web browser and navigate to `http://localhost:5002`
2. Select a network interface from the dropdown menu
3. View detailed interface information (IP, MAC, netmask, network, broadcast, MTU, status)
4. Click "Start" to begin capturing LLDP packets
5. View detected switches in real-time with automatic updates
6. Download the CSV log file or delete logs as needed

## Features in Detail

### Network Interface Display
- Real-time interface information updates every 3 seconds
- Automatic refresh when interface status changes (UP/DOWN)
- Visual feedback with amber flash animations on updates

### Switch Detection
- Real-time LLDP packet capture and parsing
- Displays switch name, port, chassis ID, MAC address, TTL, capabilities, and management IP
- Automatic updates when new switches are detected

### Log Management
- Complete detection history in CSV format
- Download logs for external analysis
- Separate controls for resetting sniffing vs deleting logs

## Network Interface Access

This application requires access to network interfaces for packet sniffing:

- **Linux**: Typically requires root/sudo access for raw socket operations
- **macOS**: May require running with sudo or granting network permissions
- **Windows**: May require Administrator privileges

### Linux - Running Without Sudo

```bash
sudo apt-get install libcap2-bin
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
```

**Note**: You may need to reapply this after Python updates.

### macOS - Network Permissions

1. System Preferences → Security & Privacy → Privacy → Full Disk Access
2. Add Terminal (or your terminal app) to the list
3. For newer macOS versions, grant network permissions

Alternatively, run with sudo if permission errors occur.

## Troubleshooting

### Cannot access network interfaces

**Linux:**
```bash
ip link show
sudo python3 app/flukenet.py
```

**macOS:**
```bash
ifconfig
sudo python3 app/flukenet.py
```

**Windows:**
```bash
ipconfig
# Run as Administrator
```

### Port already in use

Modify the port in `app/flukenet.py`:
```python
PORT = 5003  # Change to your desired port
```

### Import errors

```bash
pip3 install -r requirements.txt
# On Linux:
sudo apt-get install python3-dev libpcap-dev
```

### Interface not detected

1. Ensure proper permissions (sudo/root if needed)
2. Check that the interface exists:
   - Linux: `ip link show` or `ifconfig`
   - macOS: `ifconfig`
   - Windows: `ipconfig`
3. Make sure the interface is up and connected

## Development

### Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
pip install -r requirements.txt
python app/flukenet.py
```

### Project Structure

```
flukenet/
├── app/
│   ├── flukenet.py      # Main application
│   └── templates/
│       └── index.html   # Web UI
├── data/                # CSV logs directory (gitignored)
├── .gitignore
├── requirements.txt     # Python dependencies
└── README.md
```

