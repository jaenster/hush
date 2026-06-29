#!/usr/bin/env bash
#
# hush installer — https://github.com/jaenster/hush
#
#   curl -fsSL https://hush.typeguru.nl/install.sh | bash
#
# Downloads the latest release of hush (CLI + daemon) for macOS, verifies its
# checksum, installs the binaries, and sets up a launchd agent so hushd starts
# on login.
#
# Environment overrides:
#   HUSH_VERSION=v0.1.0   install a specific tag instead of latest
#   HUSH_BIN_DIR=~/.local/bin   install location (default: /usr/local/bin if
#                               writable, else ~/.local/bin)
#   HUSH_NO_DAEMON=1      install binaries but don't load the launchd agent
#
set -euo pipefail

REPO="jaenster/hush"
LABEL="nl.typeguru.hush"
RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"; RED="\033[31m"; GRN="\033[32m"; CYN="\033[36m"

say()  { printf "%b\n" "$1"; }
info() { printf "  %b\n" "$1"; }
die()  { printf "%b\n" "${RED}error:${RESET} $1" >&2; exit 1; }

# --- platform check -----------------------------------------------------------
[ "$(uname -s)" = "Darwin" ] || die "hush is macOS-only (detected $(uname -s))."

arch="$(uname -m)"
case "$arch" in
  arm64|aarch64) target="aarch64-macos" ;;
  x86_64)
    die "Intel (x86_64) prebuilt binaries aren't published yet.\n  Build from source: ${CYN}https://github.com/${REPO}#build${RESET}" ;;
  *) die "unsupported architecture: $arch" ;;
esac

# --- resolve version ----------------------------------------------------------
version="${HUSH_VERSION:-}"
if [ -z "$version" ]; then
  info "Resolving latest release…"
  version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')" || true
  [ -n "$version" ] || die "no published release found.\n  Build from source: ${CYN}https://github.com/${REPO}#build${RESET}"
fi

asset="hush-${version}-${target}.tar.gz"
base="https://github.com/${REPO}/releases/download/${version}"

say "${BOLD}Installing hush ${version}${RESET} (${target})"

# --- download + verify --------------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "Downloading ${asset}…"
curl -fSL --progress-bar "${base}/${asset}"        -o "${tmp}/${asset}"     || die "download failed"
curl -fsSL "${base}/${asset}.sha256"               -o "${tmp}/${asset}.sha256" || die "checksum download failed"

info "Verifying checksum…"
( cd "$tmp" && \
  expected="$(awk '{print $1}' "${asset}.sha256")" && \
  actual="$(shasum -a 256 "${asset}" | awk '{print $1}')" && \
  [ "$expected" = "$actual" ] ) || die "checksum mismatch — refusing to install"

tar -xzf "${tmp}/${asset}" -C "$tmp"

# --- choose bin dir -----------------------------------------------------------
bindir="${HUSH_BIN_DIR:-}"
if [ -z "$bindir" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then bindir="/usr/local/bin"; else bindir="$HOME/.local/bin"; fi
fi
mkdir -p "$bindir"

info "Installing to ${BOLD}${bindir}${RESET}"
for bin in hush hushd hush-bar; do
  [ -f "${tmp}/${bin}" ] || continue
  install -m 0755 "${tmp}/${bin}" "${bindir}/${bin}"
  # Strip the Gatekeeper quarantine flag set on downloaded files (binaries are
  # not yet notarized) so they run without a "developer cannot be verified" box.
  xattr -d com.apple.quarantine "${bindir}/${bin}" 2>/dev/null || true
done

# --- launchd agent ------------------------------------------------------------
if [ "${HUSH_NO_DAEMON:-0}" != "1" ]; then
  plist="$HOME/Library/LaunchAgents/${LABEL}.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${bindir}/hushd</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>${HOME}/Library/Logs/hushd.log</string>
  <key>StandardOutPath</key><string>${HOME}/Library/Logs/hushd.log</string>
</dict>
</plist>
PLIST
  info "Starting the hush daemon (launchd: ${LABEL})…"
  launchctl unload "$plist" 2>/dev/null || true
  launchctl load "$plist" 2>/dev/null || info "${DIM}could not auto-load the agent; start it with: launchctl load $plist${RESET}"
fi

# --- done ---------------------------------------------------------------------
say ""
say "${GRN}✓ hush ${version} installed.${RESET}"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) say "  ${BOLD}Add ${bindir} to your PATH:${RESET}\n    echo 'export PATH=\"${bindir}:\$PATH\"' >> ~/.zshrc && source ~/.zshrc" ;;
esac
say ""
say "  Get started:"
say "    ${CYN}hush set dev API_KEY s3cr3t${RESET}     # store a secret"
say "    ${CYN}hush -- node server.js${RESET}          # inject the env into a command"
say "    ${CYN}hush --help${RESET}"
say ""
say "  Docs: ${CYN}https://hush.typeguru.nl${RESET}"
