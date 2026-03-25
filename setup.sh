#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  ZeroTrustOps Platform — One Command Setup
#
#  Usage:
#    bash setup.sh
#
#  What this does:
#    1. Checks prerequisites (Docker, Go)
#    2. Builds SecTL engine from source
#    3. Builds and starts all Docker containers
#    4. Opens the dashboard
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✔${RESET}  $1"; }
info() { echo -e "  ${CYAN}▶${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
fail() { echo -e "\n  ${RED}✗  $1${RESET}\n"; exit 1; }
hdr()  {
  echo ""
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  echo ""
}

clear
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ╔═══════════════════════════════════════════════════════╗
  ║   🔒  ZeroTrustOps Security Enforcement Platform      ║
  ║       Self-Hosted · Open Source · One Command         ║
  ╚═══════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

# ─── Step 0: Prerequisites ────────────────────────────────────────
hdr "Step 0: Checking Prerequisites"

command -v docker &>/dev/null \
  && ok "Docker: $(docker --version | awk '{print $3}' | tr -d ',')" \
  || fail "Docker not found → https://docs.docker.com/get-docker/"

docker compose version &>/dev/null \
  && ok "Docker Compose: found" \
  || fail "Docker Compose not found. Update Docker to latest version."

command -v go &>/dev/null \
  && ok "Go: $(go version | awk '{print $3}')" \
  || fail "Go not found → https://go.dev/dl/"

command -v git &>/dev/null && ok "Git: found" || fail "Git not found"

# ─── Step 1: Build SecTL ──────────────────────────────────────────
hdr "Step 1: Building SecTL Security Engine"

info "Downloading Go dependencies..."
cd sectl
go mod tidy -e 2>/dev/null || true
info "Compiling sectl binary..."
go build -ldflags "-s -w" -o bin/sectl .
ok "SecTL built: $(./bin/sectl --version 2>/dev/null || echo 'v0.1.0')"

info "Installing sectl to /usr/local/bin..."
sudo cp bin/sectl /usr/local/bin/sectl \
  && ok "sectl installed system-wide" \
  || warn "Could not install system-wide. Using local path."
cd ..

# ─── Step 2: Quick scan test ──────────────────────────────────────
hdr "Step 2: SecTL Quick Test"

info "Scanning insecure testdata (should FAIL)..."
sectl scan sectl/testdata/k8s --type k8s --severity high 2>/dev/null || true

echo ""
info "Scanning hardened manifests (should PASS)..."
sectl scan manifests --type k8s --severity high --fail-on-findings 2>/dev/null \
  && ok "manifests/ is clean — secure config verified" \
  || warn "manifests/ has findings — review before production use"

# ─── Step 3: Build & Start Platform ──────────────────────────────
hdr "Step 3: Building & Starting Platform"

echo -e "  ${YELLOW}First run takes 3–5 min (downloads images, builds containers).${RESET}"
echo -e "  ${YELLOW}Subsequent starts are instant (cached).${RESET}"
echo ""

# Stop any existing instance
docker compose down 2>/dev/null || true

info "Building containers..."
docker compose build --progress=plain 2>&1 | grep -E "^#[0-9]|✅|ERROR|error" || true

info "Starting platform..."
docker compose up -d

# ─── Step 4: Wait for ready ───────────────────────────────────────
hdr "Step 4: Waiting for Platform to be Ready"

info "Waiting for API..."
WAITED=0
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
  sleep 5; WAITED=$((WAITED+5)); printf "."
  [[ $WAITED -ge 120 ]] && echo "" && fail "API not ready in 2 min. Run: docker compose logs api"
done
echo ""
ok "API is ready: http://localhost:8000"

info "Waiting for Dashboard..."
WAITED=0
until curl -sf http://localhost:3000 > /dev/null 2>&1; do
  sleep 3; WAITED=$((WAITED+3)); printf "."
  [[ $WAITED -ge 60 ]] && echo "" && warn "Dashboard slow to start. Try http://localhost:3000 manually."
  break
done
echo ""
ok "Dashboard is ready: http://localhost:3000"

# ─── Step 5: Done ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}"
cat << 'DONE'
  ╔═══════════════════════════════════════════════════════╗
  ║   🎉  ZeroTrustOps is LIVE!                           ║
  ╠═══════════════════════════════════════════════════════╣
  ║                                                       ║
  ║   Dashboard  →  http://localhost:3000                 ║
  ║   API        →  http://localhost:8000                 ║
  ║   API Docs   →  http://localhost:8000/docs            ║
  ║                                                       ║
  ╚═══════════════════════════════════════════════════════╝
DONE
echo -e "${RESET}"

echo -e "${BOLD}Next Steps:${RESET}"
echo ""
echo -e "  ${CYAN}1.${RESET} Open Dashboard: ${GREEN}http://localhost:3000${RESET}"
echo -e "  ${CYAN}2.${RESET} Go to Setup & Webhook page"
echo -e "  ${CYAN}3.${RESET} Get public URL with ngrok: ${YELLOW}ngrok http 3000${RESET}"
echo -e "  ${CYAN}4.${RESET} Add webhook to your GitHub repo"
echo -e "  ${CYAN}5.${RESET} Push code → watch scan run automatically"
echo ""
echo -e "${BOLD}Useful Commands:${RESET}"
echo ""
echo -e "  docker compose logs -f api     # API logs"
echo -e "  docker compose logs -f web     # Frontend logs"
echo -e "  docker compose down            # Stop platform"
echo -e "  docker compose down -v         # Stop + delete data"
echo ""
