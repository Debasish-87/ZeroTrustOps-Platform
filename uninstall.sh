#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  ZeroTrustOps Platform — Complete Uninstaller
#
#  Usage:
#    bash uninstall.sh
#
#  What this removes:
#    1. Docker containers (zerotrust-db, zerotrust-api, zerotrust-web)
#    2. Docker images (zerotrust-api:latest, zerotrust-web:latest)
#    3. Docker volumes (db_data, scan_workspace)
#    4. Docker network (zerotrust-net)
#    5. sectl binary (/usr/local/bin/sectl)
#    6. sectl compiled binary (sectl/bin/sectl)
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✔${RESET}  $1"; }
info() { echo -e "  ${CYAN}▶${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
fail() { echo -e "\n  ${RED}✗  $1${RESET}\n"; exit 1; }
skip() { echo -e "  ${YELLOW}–${RESET}  $1 (already removed)"; }
hdr()  {
  echo ""
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  echo ""
}

clear
echo -e "${BOLD}${RED}"
cat << 'BANNER'
  ╔═══════════════════════════════════════════════════════╗
  ║   🗑️   ZeroTrustOps — Complete Uninstaller            ║
  ║        Removes ALL containers, images, volumes        ║
  ╚═══════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

# ─── Confirmation ─────────────────────────────────────────────────
echo -e "  ${RED}${BOLD}WARNING: Yeh sab kuch delete kar dega:${RESET}"
echo ""
echo -e "    ${RED}•${RESET} Docker containers  (zerotrust-db, zerotrust-api, zerotrust-web)"
echo -e "    ${RED}•${RESET} Docker images      (zerotrust-api:latest, zerotrust-web:latest)"
echo -e "    ${RED}•${RESET} Docker volumes     (db_data — DATABASE PERMANENTLY DELETE HOGI!)"
echo -e "    ${RED}•${RESET} Docker volumes     (scan_workspace)"
echo -e "    ${RED}•${RESET} Docker network     (zerotrust-net)"
echo -e "    ${RED}•${RESET} sectl binary       (/usr/local/bin/sectl)"
echo -e "    ${RED}•${RESET} sectl binary       (sectl/bin/sectl)"
echo ""
read -p "  Confirm karo — aage badhna hai? (yes/no): " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
  echo ""
  warn "Uninstall cancel kar diya. Koi cheez delete nahi hui."
  echo ""
  exit 0
fi

# ─── Step 1: Docker Compose se sab stop + delete ──────────────────
hdr "Step 1: Docker Containers, Volumes & Network"

if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then

  # Containers + volumes + network ek saath
  if docker compose ps -q 2>/dev/null | grep -q .; then
    info "Containers stop kar rahe hain..."
    docker compose down --volumes --remove-orphans 2>/dev/null \
      && ok "Containers + volumes + network removed" \
      || warn "docker compose down mein kuch issue tha, manually try karte hain..."
  else
    info "Containers already band hain, volumes clean karte hain..."
    docker compose down --volumes --remove-orphans 2>/dev/null || true
    ok "Compose cleanup done"
  fi

else
  warn "Docker Compose nahi mila — manually containers check karte hain"
fi

# ─── Step 2: Containers manually remove (agar baaki reh gaye) ─────
hdr "Step 2: Remaining Containers Check"

CONTAINERS=("zerotrust-db" "zerotrust-api" "zerotrust-web")

for CONTAINER in "${CONTAINERS[@]}"; do
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    info "Force removing container: $CONTAINER"
    docker rm -f "$CONTAINER" 2>/dev/null \
      && ok "Container removed: $CONTAINER" \
      || warn "Could not remove: $CONTAINER"
  else
    skip "Container: $CONTAINER"
  fi
done

# ─── Step 3: Docker Images remove ─────────────────────────────────
hdr "Step 3: Docker Images"

IMAGES=("zerotrust-api:latest" "zerotrust-web:latest")

for IMAGE in "${IMAGES[@]}"; do
  if docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -q "^${IMAGE}$"; then
    info "Removing image: $IMAGE"
    docker rmi -f "$IMAGE" 2>/dev/null \
      && ok "Image removed: $IMAGE" \
      || warn "Could not remove image: $IMAGE"
  else
    skip "Image: $IMAGE"
  fi
done

# ─── Step 4: Docker Volumes manually remove ───────────────────────
hdr "Step 4: Docker Volumes (Database + Workspace)"

# Compose volumes ka naam project folder ke naam pe hota hai
PROJECT_NAME=$(basename "$(pwd)" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]-_')

VOLUMES=(
  "${PROJECT_NAME}_db_data"
  "${PROJECT_NAME}_scan_workspace"
  "db_data"
  "scan_workspace"
)

for VOLUME in "${VOLUMES[@]}"; do
  if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -q "^${VOLUME}$"; then
    info "Removing volume: $VOLUME"
    docker volume rm "$VOLUME" 2>/dev/null \
      && ok "Volume removed: $VOLUME" \
      || warn "Could not remove volume: $VOLUME (ho sakta hai use ho raha ho)"
  else
    skip "Volume: $VOLUME"
  fi
done

# ─── Step 5: Docker Network remove ────────────────────────────────
hdr "Step 5: Docker Network"

NETWORKS=(
  "${PROJECT_NAME}_zerotrust-net"
  "zerotrust-net"
)

for NETWORK in "${NETWORKS[@]}"; do
  if docker network ls --format '{{.Name}}' 2>/dev/null | grep -q "^${NETWORK}$"; then
    info "Removing network: $NETWORK"
    docker network rm "$NETWORK" 2>/dev/null \
      && ok "Network removed: $NETWORK" \
      || warn "Could not remove network: $NETWORK"
  else
    skip "Network: $NETWORK"
  fi
done

# ─── Step 6: sectl binary remove ──────────────────────────────────
hdr "Step 6: SecTL Binary"

# System-wide binary
if [ -f "/usr/local/bin/sectl" ]; then
  info "Removing /usr/local/bin/sectl..."
  sudo rm -f /usr/local/bin/sectl \
    && ok "sectl removed from /usr/local/bin/" \
    || warn "Could not remove /usr/local/bin/sectl (try: sudo rm /usr/local/bin/sectl)"
else
  skip "/usr/local/bin/sectl"
fi

# Local compiled binary
if [ -f "sectl/bin/sectl" ]; then
  info "Removing sectl/bin/sectl..."
  rm -f sectl/bin/sectl \
    && ok "sectl/bin/sectl removed" \
    || warn "Could not remove sectl/bin/sectl"
else
  skip "sectl/bin/sectl"
fi

# Go build cache clear (optional)
if [ -d "sectl/bin" ]; then
  rmdir sectl/bin 2>/dev/null && ok "sectl/bin/ directory removed" || true
fi

# ─── Step 7: Final verification ───────────────────────────────────
hdr "Step 7: Verification"

ERRORS=0

# Check containers
for CONTAINER in "zerotrust-db" "zerotrust-api" "zerotrust-web"; do
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    warn "Container abhi bhi hai: $CONTAINER"
    ERRORS=$((ERRORS+1))
  else
    ok "Container gone: $CONTAINER"
  fi
done

# Check images
for IMAGE in "zerotrust-api:latest" "zerotrust-web:latest"; do
  if docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -q "^${IMAGE}$"; then
    warn "Image abhi bhi hai: $IMAGE"
    ERRORS=$((ERRORS+1))
  else
    ok "Image gone: $IMAGE"
  fi
done

# Check sectl
if [ -f "/usr/local/bin/sectl" ]; then
  warn "sectl binary abhi bhi hai: /usr/local/bin/sectl"
  ERRORS=$((ERRORS+1))
else
  ok "sectl binary gone: /usr/local/bin/sectl"
fi

# ─── Done ─────────────────────────────────────────────────────────
echo ""
if [ $ERRORS -eq 0 ]; then
  echo -e "${BOLD}${GREEN}"
  cat << 'DONE'
  ╔═══════════════════════════════════════════════════════╗
  ║   ✅  Uninstall Complete!                             ║
  ║       Sab kuch clean ho gaya.                        ║
  ╚═══════════════════════════════════════════════════════╝
DONE
  echo -e "${RESET}"
  echo -e "  ${GREEN}ZeroTrustOps platform completely removed.${RESET}"
  echo -e "  ${CYAN}Project files (code) abhi bhi hain — sirf runtime sab clean hua.${RESET}"
  echo ""
  echo -e "  Dobara install karna ho toh:  ${YELLOW}bash setup.sh${RESET}"
  echo ""
else
  echo -e "${BOLD}${YELLOW}"
  cat << 'PARTIAL'
  ╔═══════════════════════════════════════════════════════╗
  ║   ⚠️   Partial Uninstall                              ║
  ║       Kuch cheezein manually remove karni padegi     ║
  ╚═══════════════════════════════════════════════════════╝
PARTIAL
  echo -e "${RESET}"
  warn "$ERRORS item(s) manually remove karne padenge (upar warnings dekho)"
  echo ""
  echo -e "  Manual commands:"
  echo -e "    ${YELLOW}sudo rm -f /usr/local/bin/sectl${RESET}"
  echo -e "    ${YELLOW}docker rm -f zerotrust-db zerotrust-api zerotrust-web${RESET}"
  echo -e "    ${YELLOW}docker rmi zerotrust-api:latest zerotrust-web:latest${RESET}"
  echo -e "    ${YELLOW}docker volume prune${RESET}"
  echo ""
fi
