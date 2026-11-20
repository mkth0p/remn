#!/bin/bash
# Lets the Ollama app on this Mac answer a REMN page served from another host, for good.
#
#   curl -fsSL https://remn.tech/ollama-mac.sh | bash
#   curl -fsSL https://remn.example.com/ollama-mac.sh | bash -s -- https://remn.example.com
#
# 1. adds the origin to OLLAMA_ORIGINS now (launchctl setenv; the menu-bar app does not read
#    shell exports) and at every login, through a LaunchAgent that runs before Ollama starts
# 2. restarts Ollama so it reads the variable, and checks it answers the origin
#
# It installs nothing and pulls no model.
#
# Undo: launchctl unload ~/Library/LaunchAgents/tech.remn.ollama-origins.plist, delete that
# file, launchctl unsetenv OLLAMA_ORIGINS, and restart Ollama.
set -euo pipefail

ORIGIN="${1:-${REMN_ORIGIN:-https://remn.tech}}"
ORIGIN="${ORIGIN%/}"
OLLAMA="${OLLAMA_URL:-http://127.0.0.1:11434}"
LABEL="tech.remn.ollama-origins"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || fail "this script is for macOS; on Linux use systemctl edit ollama, on Windows setx OLLAMA_ORIGINS"
case "$ORIGIN" in
  http://* | https://*) ;;
  *) fail "origin must start with http:// or https:// (got: $ORIGIN)" ;;
esac
case "$ORIGIN" in
  *[[:space:]\",\<\>\&]* | */*/*/*) fail "origin must be scheme://host[:port], nothing more (got: $ORIGIN)" ;;
esac

# Ollama installed?
if [ ! -d /Applications/Ollama.app ] && [ ! -d "$HOME/Applications/Ollama.app" ] && ! command -v ollama >/dev/null 2>&1; then
  fail "Ollama is not installed: download it from https://ollama.com/download/mac, open it once, then run this again"
fi

# keep origins set earlier (another REMN, a local tool), add this one
CURRENT="$(launchctl getenv OLLAMA_ORIGINS 2>/dev/null || true)"
ORIGINS="$ORIGIN"
if [ -n "$CURRENT" ]; then
  IFS=',' read -r -a parts <<<"$CURRENT"
  for p in "${parts[@]}"; do
    p="$(printf '%s' "$p" | tr -d '[:space:]')"
    [ -n "$p" ] && [ "$p" != "$ORIGIN" ] && ORIGINS="$ORIGINS,$p"
  done
fi

say "Allowing $ORIGINS"
launchctl setenv OLLAMA_ORIGINS "$ORIGINS"

mkdir -p "$HOME/Library/LaunchAgents"
cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/launchctl</string>
    <string>setenv</string>
    <string>OLLAMA_ORIGINS</string>
    <string>$ORIGINS</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
EOF
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

say "Restarting Ollama"
osascript -e 'tell application "Ollama" to quit' >/dev/null 2>&1 || true
pkill -x ollama >/dev/null 2>&1 || true
for _ in $(seq 1 20); do pgrep -x ollama >/dev/null 2>&1 || break; sleep 0.5; done
if [ -d /Applications/Ollama.app ] || [ -d "$HOME/Applications/Ollama.app" ]; then
  open -a Ollama
else
  nohup env OLLAMA_ORIGINS="$ORIGINS" ollama serve >/dev/null 2>&1 &
fi
up=""
for _ in $(seq 1 60); do
  if curl -fs "$OLLAMA/api/version" >/dev/null 2>&1; then up=1; break; fi
  sleep 0.5
done
[ -n "$up" ] || fail "Ollama did not come back at $OLLAMA; open the Ollama app and run this again"

allow="$(curl -s -o /dev/null -D - -H "Origin: $ORIGIN" "$OLLAMA/api/tags" | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}')"
if [ "$allow" = "$ORIGIN" ] || [ "$allow" = "*" ]; then
  say "Ollama answers $ORIGIN"
else
  fail "Ollama still refuses $ORIGIN; quit it from the menu bar, open it again and re-run this script"
fi

say "Done. Open $ORIGIN, Settings, AI: Browser-direct at http://localhost:11434, and press test."
echo "Use Chrome, Edge or Firefox (Safari blocks https pages from calling localhost), and allow the local-network prompt if one shows."
