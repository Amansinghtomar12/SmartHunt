#!/usr/bin/env bash
#
# Install the optional external tools SmartHunt can drive.
#
#   ./install-tools.sh          Go-based tools only (the bulk of them)
#   ./install-tools.sh --all    also pip/pipx and apt packages
#   ./install-tools.sh --check  just report what is already installed
#
# Everything here is optional — SmartHunt falls back to built-in pure-Python
# modules for anything that is missing.

set -uo pipefail

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'
MODE="${1:-go}"

GO_TOOLS=(
  "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "assetfinder:github.com/tomnomnom/assetfinder@latest"
  "chaos:github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
  "github-subdomains:github.com/gwen001/github-subdomains@latest"
  "shosubgo:github.com/incogbyte/shosubgo@latest"
  "gotator:github.com/Josue87/gotator@latest"
  "puredns:github.com/d3mondev/puredns/v2@latest"
  "shuffledns:github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "httprobe:github.com/tomnomnom/httprobe@latest"
  "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
  "gau:github.com/lc/gau/v2/cmd/gau@latest"
  "waybackurls:github.com/tomnomnom/waybackurls@latest"
  "hakrawler:github.com/hakluke/hakrawler@latest"
  "gospider:github.com/jaeles-project/gospider@latest"
  "urlfinder:github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
  "subjs:github.com/lc/subjs@latest"
  "getJS:github.com/003random/getJS@latest"
  "jsluice:github.com/BishopFox/jsluice/cmd/jsluice@latest"
  "mantra:github.com/MrEmpy/mantra@latest"
  "unfurl:github.com/tomnomnom/unfurl@latest"
  "qsreplace:github.com/tomnomnom/qsreplace@latest"
  "ffuf:github.com/ffuf/ffuf/v2@latest"
  "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "dalfox:github.com/hahwul/dalfox/v2@latest"
  "crlfuzz:github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  "subzy:github.com/PentestPad/subzy@latest"
  "subjack:github.com/haccer/subjack@latest"
  "gowitness:github.com/sensepost/gowitness@latest"
  "trufflehog:github.com/trufflesecurity/trufflehog/v3@latest"
  "gitleaks:github.com/gitleaks/gitleaks/v8@latest"
)

PIP_TOOLS=("dnsgen" "py-altdns" "paramspider" "arjun" "dirsearch" "sqlmap" "xnLinkFinder")
APT_TOOLS=("nmap" "masscan")

ALL_NAMES=(
  subfinder assetfinder amass findomain chaos github-subdomains shosubgo
  dnsgen gotator altdns puredns shuffledns massdns dnsx httpx httprobe
  naabu nmap masscan katana gau waybackurls hakrawler gospider urlfinder
  subjs getJS jsluice linkfinder secretfinder xnLinkFinder mantra
  paramspider arjun unfurl qsreplace ffuf feroxbuster dirsearch kiterunner
  nuclei dalfox crlfuzz sqlmap corsy smuggler subzy subjack gowitness
  aquatone trufflehog gitleaks
)

check() {
  local found=0 total=0
  echo -e "\n${DIM}Checking PATH (and ~/go/bin, ~/.local/bin)…${NC}\n"
  for name in "${ALL_NAMES[@]}"; do
    total=$((total + 1))
    if command -v "$name" >/dev/null 2>&1 \
       || [ -x "$HOME/go/bin/$name" ] || [ -x "$HOME/.local/bin/$name" ]; then
      echo -e "  ${GREEN}●${NC} $name"
      found=$((found + 1))
    else
      echo -e "  ${DIM}○ $name${NC}"
    fi
  done
  echo -e "\n${GREEN}$found${NC}/$total installed\n"
}

install_go() {
  if ! command -v go >/dev/null 2>&1; then
    echo -e "${RED}Go is not installed.${NC}"
    echo "Install it from https://go.dev/dl/ then re-run this script."
    return 1
  fi
  echo -e "${GREEN}Installing Go-based tools…${NC} ${DIM}(this takes a while)${NC}\n"
  local ok=0 fail=0
  for entry in "${GO_TOOLS[@]}"; do
    local name="${entry%%:*}" pkg="${entry#*:}"
    if command -v "$name" >/dev/null 2>&1 || [ -x "$HOME/go/bin/$name" ]; then
      echo -e "  ${DIM}○ $name already installed, skipping${NC}"
      continue
    fi
    printf "  installing %-20s" "$name"
    if go install -v "$pkg" >/dev/null 2>&1; then
      echo -e "${GREEN}ok${NC}"
      ok=$((ok + 1))
    else
      echo -e "${RED}failed${NC}"
      fail=$((fail + 1))
    fi
  done
  echo -e "\n${GREEN}$ok installed${NC}, ${RED}$fail failed${NC}"

  case ":$PATH:" in
    *":$HOME/go/bin:"*) ;;
    *) echo -e "\n${YELLOW}Add Go's bin directory to your PATH:${NC}"
       echo '  echo '"'"'export PATH=$PATH:$HOME/go/bin'"'"' >> ~/.bashrc && source ~/.bashrc' ;;
  esac
}

install_pip() {
  local runner=""
  if command -v pipx >/dev/null 2>&1; then
    runner="pipx install"
  elif command -v pip3 >/dev/null 2>&1; then
    runner="pip3 install --user"
  else
    echo -e "${YELLOW}Neither pipx nor pip3 found — skipping Python tools.${NC}"
    return
  fi
  echo -e "\n${GREEN}Installing Python-based tools…${NC}\n"
  for name in "${PIP_TOOLS[@]}"; do
    printf "  installing %-20s" "$name"
    if $runner "$name" >/dev/null 2>&1; then
      echo -e "${GREEN}ok${NC}"
    else
      echo -e "${YELLOW}skipped${NC}"
    fi
  done
}

install_apt() {
  command -v apt-get >/dev/null 2>&1 || return
  echo -e "\n${GREEN}Installing apt packages…${NC} ${DIM}(needs sudo)${NC}\n"
  for name in "${APT_TOOLS[@]}"; do
    command -v "$name" >/dev/null 2>&1 && continue
    printf "  installing %-20s" "$name"
    if sudo apt-get install -y "$name" >/dev/null 2>&1; then
      echo -e "${GREEN}ok${NC}"
    else
      echo -e "${YELLOW}skipped${NC}"
    fi
  done
}

case "$MODE" in
  --check|-c) check ;;
  --all|-a)   install_go; install_pip; install_apt; check ;;
  --help|-h)  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' ;;
  *)          install_go
              echo -e "\n${DIM}Run with --all to also install pip and apt tools.${NC}"
              check ;;
esac
