# LLDP Switch Logger

Real-time LLDP switch detection with CSV logging and universal compatibility.

## Features
- Live switch detection
- Full CSV history (latest on top)
- Reset + Stop + Download
- Auto interface detection
- Direct access to local network interfaces

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Linux: Root or sudo access for network interface access (packet sniffing)
- macOS: May require running with sudo for packet capture
- Windows: May require running as Administrator

## Installation

### Step 1: Clone or Download

```bash
git clone <repository-url>
cd lldp-switch-logger
```

Or download and extract the repository to a directory.

### Step 2: Install Dependencies

**Linux:**
```bash
# Install system dependencies (if needed)
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev libpcap-dev

# Install Python packages
pip3 install -r requirements.txt
```

**macOS:**
```bash
# Install Python packages
pip3 install -r requirements.txt

# If you encounter issues with libpcap, install via Homebrew:
brew install libpcap
```

**Windows:**
```bash
# Install Python packages
pip install -r requirements.txt

# Note: Packet capture on Windows may require additional setup
# Consider using WSL2 (Windows Subsystem for Linux) for better compatibility
```

### Step 3: Run the Application

**Linux (may require sudo for packet capture):**
```bash
# Try without sudo first
python3 app/lldp_app.py

# If you get permission errors for packet capture, use sudo:
sudo python3 app/lldp_app.py
```

**macOS:**
```bash
# Try without sudo first
python3 app/lldp_app.py

# If you get permission errors for packet capture, use sudo:
sudo python3 app/lldp_app.py
```

**Windows:**
```bash
# Run normally
python app/lldp_app.py

# If you encounter issues, try running as Administrator
```

The application will be available at `http://localhost:5002`

## Usage

1. Open your web browser and navigate to `http://localhost:5002`
2. Select a network interface from the dropdown menu
3. Click "Start" to begin capturing LLDP packets
4. View detected switches in real-time
5. Download the CSV log file to save your results

## Network Interface Access

This application requires access to network interfaces for packet sniffing:

- **Linux**: Typically requires root/sudo access for raw socket operations
- **macOS**: May require running with sudo or granting network permissions
- **Windows**: May require Administrator privileges

### Linux - Running Without Sudo

If you want to run without sudo on Linux, you can set capabilities:

```bash
# Install libcap2-bin if not already installed
sudo apt-get install libcap2-bin

# Set capabilities on Python (allows packet capture without full root)
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
```

**Note**: This allows Python to capture packets without running as root, but you may need to reapply this after Python updates.

### macOS - Network Permissions

On macOS, you may need to grant network permissions:

1. Go to System Preferences → Security & Privacy → Privacy → Full Disk Access
2. Add Terminal (or your terminal app) to the list
3. For newer macOS versions, you may also need to grant network permissions

Alternatively, run with sudo if permission errors occur.

## Troubleshooting

### Cannot access network interfaces

**Linux:**
```bash
# Check if you have the required permissions
ip link show

# If you get permission denied, run with sudo:
sudo python3 app/lldp_app.py
```

**macOS:**
```bash
# List available interfaces
ifconfig

# If packet capture fails, try with sudo:
sudo python3 app/lldp_app.py
```

**Windows:**
```bash
# List available interfaces
ipconfig

# If packet capture fails, try running as Administrator
```

### Port already in use

If port 5002 is already in use, you can modify the port in `app/lldp_app.py`:

```python
PORT = 5003  # Change to your desired port
```

Then restart the application.

### Import errors

If you encounter import errors:

```bash
# Make sure all dependencies are installed
pip3 install -r requirements.txt

# On Linux, ensure system libraries are installed:
sudo apt-get install python3-dev libpcap-dev
```

### Interface not detected

1. Ensure you have proper permissions (sudo/root if needed)
2. Check that the interface exists:
   - Linux: `ip link show` or `ifconfig`
   - macOS: `ifconfig`
   - Windows: `ipconfig`
3. Make sure the interface is up and connected

### Permission denied errors

**Linux:**
- Run with `sudo python3 app/lldp_app.py`
- Or set capabilities (see "Running Without Sudo" section above)

**macOS:**
- Run with `sudo python3 app/lldp_app.py`
- Or grant network permissions in System Preferences

**Windows:**
- Run as Administrator
- Or use WSL2 for better compatibility

## Development

### Virtual Environment (Recommended)

It's recommended to use a virtual environment:

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app/lldp_app.py
```

### Project Structure

```
lldp-switch-logger/
├── app/
│   ├── lldp_app.py      # Main application
│   └── templates/
│       └── index.html   # Web UI
├── data/                # CSV logs directory
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## License

[Your License Here]
