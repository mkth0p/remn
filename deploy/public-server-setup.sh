#!/usr/bin/env bash
# Prepare a fresh Ubuntu or Debian machine for a public REMN instance, then start it.
#
#   sudo REMN_DOMAIN=remn.example.tech bash deploy/public-server-setup.sh
#
# What it does: installs Docker and the firewall, opens 22/80/443 and nothing else, turns on
# unattended security updates, refuses SSH passwords (only once a key is in place, so it cannot
# lock you out), and starts docker-compose.public.yml. Run it from a clone of the repository.
#
# It is safe to run again: every step checks its own state first.
set -euo pipefail

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run with sudo: sudo REMN_DOMAIN=... bash $0"
: "${REMN_DOMAIN:?set REMN_DOMAIN to the name browsers will use, e.g. REMN_DOMAIN=remn.example.tech}"
[ -f docker-compose.public.yml ] || die "run this from the repository clone (docker-compose.public.yml is not here)"

# The user who invoked sudo owns the keys that matter; root's own keys count on a freshly created machine.
ADMIN="${SUDO_USER:-root}"
ADMIN_HOME=$(getent passwd "$ADMIN" | cut -d: -f6)

log "Checking that $REMN_DOMAIN points at this machine"
public_ip=$(curl -fsS --max-time 10 https://api.ipify.org || echo "")
resolved=$(getent ahostsv4 "$REMN_DOMAIN" | awk '{print $1; exit}' || echo "")
if [ -z "$resolved" ]; then
  die "$REMN_DOMAIN does not resolve yet. Add an A record to this machine's address (${public_ip:-unknown}) and wait for it, or Caddy's certificate request will fail and back off."
elif [ -n "$public_ip" ] && [ "$resolved" != "$public_ip" ]; then
  printf '  warning: %s resolves to %s, this machine appears to be %s\n' "$REMN_DOMAIN" "$resolved" "$public_ip"
  printf '  continuing in 10s; interrupt now if that is wrong\n'
  sleep 10
else
  printf '  %s -> %s\n' "$REMN_DOMAIN" "$resolved"
fi

log "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get -y -qq upgrade
apt-get -y -qq install ufw unattended-upgrades fail2ban curl git ca-certificates

# Docker comes from Docker's own repository rather than the distribution's: Ubuntu 20.04 has no
# docker-compose-v2 package at all, and where docker.io exists it lags. One source covers
# Ubuntu 20.04 to 24.04 and Debian, on both amd64 and arm64.
if ! docker compose version >/dev/null 2>&1; then
  . /etc/os-release
  distro="ubuntu"
  [ "${ID:-ubuntu}" = "debian" ] && distro="debian"
  codename="${VERSION_CODENAME:-}"
  [ -n "$codename" ] || die "cannot determine the distribution codename from /etc/os-release"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$distro $codename stable" >/etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get -y -qq install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker >/dev/null
docker compose version | sed 's/^/  /'

log "Firewall: 22, 80 and 443 only"

# Some cloud images (Oracle's Ubuntu among them) ship a saved iptables ruleset that rejects
# everything except SSH, restored at every boot by netfilter-persistent. Two things follow. It sits
# in front of ufw, so opening 80 and 443 in ufw and in the cloud firewall is not enough and the
# certificate request fails with no obvious cause. And ufw persists its own rules through its own
# unit, so leaving netfilter-persistent enabled means the two fight over the table and the saved
# snapshot wins at the next boot. The ruleset is moved aside, keeping a copy, and its service stopped.
for f in /etc/iptables/rules.v4 /etc/iptables/rules.v6; do
  if [ -f "$f" ] && grep -qE 'REJECT|DROP' "$f" && ! grep -q 'ufw' "$f"; then
    printf '  %s would block 80 and 443 in front of ufw and return at boot; moving it aside\n' "$f"
    mv "$f" "$f.before-remn.$(date +%Y%m%d-%H%M%S)"
  fi
done
systemctl disable --now netfilter-persistent >/dev/null 2>&1 || true

# Opens the INPUT policy and empties the chain on every backend present. Called before ufw builds
# its chains, and again if ufw fails to apply, so a half-configured firewall never seals the machine.
open_the_policy() {
  for cmd in iptables ip6tables iptables-legacy ip6tables-legacy; do
    command -v "$cmd" >/dev/null 2>&1 || continue
    "$cmd" -P INPUT ACCEPT 2>/dev/null || true
    "$cmd" -F INPUT 2>/dev/null || true
  done
}
# Clear the live table before ufw builds its chains: an empty chain with a DROP policy would cut
# the SSH session running this script, so the policy is opened first.
open_the_policy

ufw --force disable >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
for port in 22/tcp 80/tcp 443/tcp; do ufw allow "$port" >/dev/null; done
ufw_said=$(ufw --force enable 2>&1 || true)

# ufw records itself as enabled in its own configuration before, and independently of, applying
# any rules, so `ufw status` reports the full rule list even when the apply failed. Match a chain
# that exists only once the rules are genuinely live, on the backend the iptables command uses.
if iptables -S 2>/dev/null | grep -q 'ufw-before-input'; then
  systemctl enable ufw >/dev/null 2>&1 || true
  ufw status verbose | sed 's/^/  /'
else
  # A failed apply leaves DROP policies with no accept rules, which cuts every connection to the
  # machine including this session. Roll it back rather than leave the operator locked out.
  ufw --force disable >/dev/null 2>&1 || true
  open_the_policy
  printf '  WARNING: ufw could not apply its rules on this kernel, so the host firewall is OFF.\n'
  printf '  The machine stays reachable; it is not sealed. ufw said:\n'
  printf '%s\n' "$ufw_said" | sed 's/^/    /'
  printf '  Your provider firewall is now the only layer. Check it allows 22, 80 and 443 and\n'
  printf '  nothing else (Oracle: the VCN security list; AWS: the security group) before treating\n'
  printf '  this machine as hardened. The container publishes no port of its own either way.\n'
fi

log "Automatic security updates"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
systemctl enable --now fail2ban >/dev/null 2>&1 || true

log "SSH: keys only"
keys=0
for f in "$ADMIN_HOME/.ssh/authorized_keys" /root/.ssh/authorized_keys; do
  [ -s "$f" ] || continue
  keys=$((keys + $(awk 'NF && $1 !~ /^#/' "$f" | wc -l)))
done
if [ "$keys" -eq 0 ]; then
  printf '  no authorized SSH key found for %s or root: leaving password logins on, or you would be locked out.\n' "$ADMIN"
  printf '  add a key (ssh-copy-id) and run this script again to close them.\n'
else
  install -d -m 755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/10-remn.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
  if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    printf '  password logins off (%s key(s) in place). Keep this session open and test a new one before closing it.\n' "$keys"
  else
    rm -f /etc/ssh/sshd_config.d/10-remn.conf
    printf '  the SSH configuration did not validate; left unchanged.\n'
  fi
fi

log "Building and starting REMN in browser-only mode"
REMN_DOMAIN="$REMN_DOMAIN" docker compose -f docker-compose.public.yml up -d --build

log "Waiting for the certificate and the first answer"
for _ in $(seq 1 30); do
  code=$(curl -fsS -o /dev/null -w '%{http_code}' -H 'X-Forensic-Client: remn' "https://$REMN_DOMAIN/api/health" 2>/dev/null || echo 000)
  [ "$code" = "200" ] && break
  sleep 5
done
if [ "${code:-000}" = "200" ]; then
  mode=$(curl -fsS -H 'X-Forensic-Client: remn' "https://$REMN_DOMAIN/api/health" | grep -o '"mode": *"[^"]*"' || echo "?")
  log "Ready: https://$REMN_DOMAIN  ($mode)"
else
  printf '\n  not answering yet (last code %s). The certificate can take a minute on the first start.\n' "${code:-000}"
  printf '  watch it with: docker compose -f docker-compose.public.yml logs -f caddy\n'
fi
