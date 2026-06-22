#!/usr/bin/env bash
# preflight.sh — check a Linux VM is ready to run the exectrace LIVE pipeline
# (eBPF sensor + real LLM). Run this ON THE VM before `make generate`/`make live`.
# Prints green/red per requirement; exits non-zero if any hard requirement fails.
set -u

green() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
red()   { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=1; }
warn()  { printf '  \033[33m!\033[0m %s\n' "$1"; }
FAIL=0

echo "exectrace live preflight"
echo "========================"

# --- OS / arch ---
echo "platform:"
OS=$(uname -s)
if [ "$OS" = "Linux" ]; then green "OS is Linux ($(uname -m))"; else red "OS is $OS — eBPF needs Linux (not macOS). Run this inside the VM."; fi

# --- kernel version >= 5.8 (ring buffer) ---
echo "kernel:"
KREL=$(uname -r)
KMAJ=$(echo "$KREL" | cut -d. -f1)
KMIN=$(echo "$KREL" | cut -d. -f2 | sed 's/[^0-9].*//')
if [ "${KMAJ:-0}" -gt 5 ] || { [ "${KMAJ:-0}" -eq 5 ] && [ "${KMIN:-0}" -ge 8 ]; }; then
  green "kernel $KREL (>= 5.8, ring buffer OK)"
else
  red "kernel $KREL is < 5.8 — ring buffer eBPF needs 5.8+"
fi

# --- BTF present (bpf2go / CO-RE) ---
echo "BTF:"
if [ -r /sys/kernel/btf/vmlinux ]; then
  green "/sys/kernel/btf/vmlinux present (CO-RE OK)"
else
  red "/sys/kernel/btf/vmlinux missing — install a BTF-enabled kernel / linux-headers, or make generate will fail"
fi

# --- toolchain ---
echo "toolchain:"
for t in clang go node npm; do
  if command -v "$t" >/dev/null 2>&1; then
    green "$t ($($t --version 2>/dev/null | head -1))"
  else
    if [ "$t" = "node" ] || [ "$t" = "npm" ]; then
      warn "$t not found — only needed for 'make ui' (frontend rebuild); a committed dist/ still works"
    else
      red "$t not found — required to build (clang for bpf2go, go for binaries)"
    fi
  fi
done

# --- root (eBPF load needs CAP_BPF / root) ---
echo "privileges:"
if [ "$(id -u)" -eq 0 ]; then
  green "running as root"
elif sudo -n true 2>/dev/null; then
  green "passwordless sudo available"
elif command -v sudo >/dev/null 2>&1; then
  warn "sudo present but may prompt for a password (fine — 'make live' uses sudo)"
else
  red "no root / sudo — eBPF load requires root"
fi

# --- Ollama (the real LLM scorer) ---
echo "ollama (real LLM scorer):"
if curl -sf -m 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
  green "Ollama responding on :11434"
  MODELS=$(curl -sf -m 2 http://localhost:11434/api/tags 2>/dev/null)
  if echo "$MODELS" | grep -q "llama3.2:1b"; then
    green "model llama3.2:1b is pulled"
  else
    warn "llama3.2:1b not pulled — run: ollama pull llama3.2:1b   (or pass make live MODEL=<name>)"
  fi
else
  red "Ollama not reachable on :11434 — run 'ollama serve &' and 'ollama pull llama3.2:1b'"
fi

# --- resources (1B model wants headroom) ---
echo "resources:"
if command -v free >/dev/null 2>&1; then
  MEM=$(free -m | awk '/^Mem:/{print $2}')
  if [ "${MEM:-0}" -ge 3000 ]; then green "RAM ${MEM}MB (>= 3GB)"; else warn "RAM ${MEM}MB — llama3.2:1b is happier with >= 3-4GB; verdicts may be slow"; fi
fi
green "CPUs: $(nproc 2>/dev/null || echo '?')"

echo "========================"
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mREADY\033[0m — build P1 (make generate && make build), then exectrace (make ui && make build), then: make live\n'
  exit 0
else
  printf '\033[31mNOT READY\033[0m — fix the ✗ items above first.\n'
  exit 1
fi
