#!/bin/bash
# netwatch dashboard installer

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "\n${CYAN}╔══════════════════════════════════════╗"
echo -e "║   NETWATCH Dashboard Installer       ║"
echo -e "╚══════════════════════════════════════╝${NC}\n"

[ "$EUID" -ne 0 ] && echo -e "${YELLOW}[!] Run as root: sudo bash install_dashboard.sh${NC}" && exit 1

echo -e "${GREEN}[*] Installing system dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq nmap arp-scan python3 python3-pip

echo -e "${GREEN}[*] Installing Python packages...${NC}"
pip3 install flask --break-system-packages -q 2>/dev/null || pip3 install flask -q

echo -e "${GREEN}[✓] All dependencies installed${NC}"

echo -e "\n${CYAN}════════════════════════════════════════"
echo -e "  Ready! Start the dashboard with:"
echo -e "  ${YELLOW}sudo python3 app.py${NC}"
echo -e "${CYAN}  Then open: ${YELLOW}http://localhost:5000${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}\n"
