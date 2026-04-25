#!/bin/bash

# Husn (حصن) - Universal Setup Script
# Target OS: Kali Linux, Ubuntu, Debian, CentOS, RHEL

set -e

echo "🛡️ Starting Husn (حصن) Universal Setup..."

# Function to detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        OS=$(uname -s)
    fi
    echo "Detected OS: $OS"
}

detect_os

# Install System Dependencies
case "$OS" in
    ubuntu|debian|kali)
        echo "Updating apt and installing dependencies..."
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv nodejs npm libcap2-bin git
        ;;
    centos|rhel|rocky)
        echo "Installing dependencies via dnf/yum..."
        sudo dnf install -y python3 python3-pip nodejs npm libcap git
        ;;
    *)
        echo "Unsupported OS: $OS. Please install Python3, Node.js, and npm manually."
        ;;
esac

# Create Virtual Environment for Backend
echo "Setting up Python Virtual Environment..."
cd backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cd ..

# Install Frontend Dependencies
echo "Setting up Frontend (React)..."
cd frontend
npm install
cd ..

# Scapy Raw Socket Permissions
echo "Configuring Scapy permissions..."
PYTHON_PATH=$(which python3)
if [ -f "$PYTHON_PATH" ]; then
    sudo setcap cap_net_raw,cap_net_admin=eip "$PYTHON_PATH"
    echo "✓ Scapy permissions configured for $PYTHON_PATH"
else
    echo "⚠️ Could not find python3 to set capabilities. Scapy might require sudo."
fi

echo "✅ Husn Setup Complete!"
echo "To start the system, run: python3 run.py both"
