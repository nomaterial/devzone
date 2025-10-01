#!/usr/bin/env bash
# devnet.sh — Réseau libvirt "Dev zone" NATé via wg0-mullvad, DNS Mullvad, fail-closed.
# Usage: sudo ./devnet.sh {up|down|status}

sudo -v || exit 1
set -euo pipefail

# --- Paramètres ---
URI="qemu:///system"
NET_NAME="devnet"
WG_IF="wg0-mullvad"
BR_NAME="virbr2"
SUBNET_V4="10.88.0.0/24"
GW_V4="10.88.0.1"
DNS_MULLVAD_INTERNAL="10.64.0.1"
XML_FILE="/tmp/${NET_NAME}.xml"
STATE_DIR="/run/${NET_NAME}"
IPFWD_FILE="${STATE_DIR}/ip_forward.prev"

# --- Utilitaires ---
have()    { command -v "$1" >/dev/null 2>&1; }
die()     { echo "[-] $*" >&2; exit 1; }
require() { for c in "$@"; do have "$c" || die "commande manquante: $c"; done; }
vsh()     { LC_ALL=C sudo virsh -c "$URI" "$@"; }

# --- État réseau libvirt ---
net_defined() { vsh net-info "$NET_NAME" >/dev/null 2>&1; }
net_active()  { vsh net-info "$NET_NAME" 2>/dev/null | awk -F': *' '/^Active:/ {print tolower($2)}' | grep -q yes; }
bridge_name() { vsh net-info "$NET_NAME" 2>/dev/null | awk -F': *' '/^Bridge:/ {print $2}'; }

# --- Démarrage daemons (on-demand) ---
start_daemons() {
  local sockets=(
    libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket
    virtqemud.socket virtnetworkd.socket virtlogd.socket virtlockd.socket
    virtstoraged.socket virtproxyd.socket virtproxyd-admin.socket
  )
  sudo systemctl start "${sockets[@]}" 2>/dev/null || true
  for _ in {1..60}; do
    [[ -S /run/libvirt/libvirt-sock      || -S /var/run/libvirt/libvirt-sock      ]] && api=1 || api=0
    [[ -S /run/libvirt/virtqemud-sock    || -S /var/run/libvirt/virtqemud-sock    ]] && qemu=1 || qemu=0
    [[ -S /run/libvirt/virtnetworkd-sock || -S /var/run/libvirt/virtnetworkd-sock ]] && netd=1 || netd=0
    [[ -S /run/libvirt/virtstoraged-sock || -S /var/run/libvirt/virtstoraged-sock ]] && stor=1 || stor=0
    [[ $api -eq 1 && $qemu -eq 1 && $netd -eq 1 && $stor -eq 1 ]] && break
    sleep 0.2
  done
  [[ ${api:-0}  -eq 1 ]] || die "aucun socket API libvirt"
  [[ ${qemu:-0} -eq 1 ]] || die "virtqemud-sock absent"
  [[ ${netd:-0} -eq 1 ]] || die "virtnetworkd-sock absent"
  [[ ${stor:-0} -eq 1 ]] || die "virtstoraged-sock absent"
}

stop_daemons() {
  sudo systemctl stop \
    libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket \
    virtqemud.socket virtnetworkd.socket virtlogd.socket virtlockd.socket \
    virtstoraged.socket virtproxyd.socket virtproxyd-admin.socket 2>/dev/null || true
}

# --- XML réseau (NAT via wg0-mullvad + DNS Mullvad interne) ---
write_xml() {
  cat > "$XML_FILE" <<XML
<network xmlns:dnsmasq="http://libvirt.org/schemas/network/dnsmasq/1.0">
  <name>${NET_NAME}</name>
  <forward mode='nat' dev='${WG_IF}'/>
  <bridge name='${BR_NAME}' stp='on' delay='0'/>
  <dns>
    <dnsmasq:option value="no-resolv"/>
    <dnsmasq:option value="server=${DNS_MULLVAD_INTERNAL}"/>
  </dns>
  <ip address='${GW_V4}' netmask='255.255.255.0'>
    <dhcp>
      <range start='10.88.0.100' end='10.88.0.199'/>
    </dhcp>
  </ip>
</network>
XML
}

# --- nftables guard (fail-closed, DNS forcé, egress=wg0) ---
nft_up() {
  sudo nft -f - <<'NFT'
table inet devnet_guard {
  chain forward {
    type filter hook forward priority -200;
    policy drop;

    ct state established,related accept
    iifname { "virbr2", "vnet*" } ip saddr != 10.88.0.0/24 drop

    ip saddr 10.88.0.0/24 ip daddr 10.88.0.1 udp dport {53,67} accept
    ip saddr 10.88.0.1     ip daddr 10.88.0.0/24 udp sport {53,67} accept
    ip saddr 10.88.0.0/24 ip daddr 10.88.0.1 tcp dport 53 accept
    ip saddr 10.88.0.1     ip daddr 10.88.0.0/24 tcp sport 53 accept

    iifname { "virbr2", "vnet*" } udp dport 53 ip daddr != 10.88.0.1 drop
    iifname { "virbr2", "vnet*" } tcp dport 53 ip daddr != 10.88.0.1 drop

    ip saddr 10.88.0.0/24 oifname "wg0-mullvad" accept

    iifname { "virbr2", "vnet*" } meta l4proto ipv6-icmp drop
    iifname { "virbr2", "vnet*" } ip6 saddr ::/0 drop
  }
}
NFT
}

nft_down() {
  sudo nft list tables 2>/dev/null | grep -q "^table inet devnet_guard$" && \
    sudo nft delete table inet devnet_guard || true
}

# --- Exceptions Mullvad (forward précis virbr2 <-> wg0) ---
mullvad_fix_forward() {
  have nft || return 0
  # VM -> Internet via wg0
  if ! sudo nft list chain inet mullvad forward 2>/dev/null | \
       grep -q 'ip saddr 10\.88\.0\.0/24 .* iifname "virbr2" .* oifname "wg0-mullvad" .* accept'; then
    sudo nft insert rule inet mullvad forward \
      ip saddr 10.88.0.0/24 iifname "virbr2" oifname "wg0-mullvad" accept || true
  fi
  # Retours Internet -> VM
  if ! sudo nft list chain inet mullvad forward 2>/dev/null | \
       grep -q 'ct state established,related .* iifname "wg0-mullvad" .* oifname "virbr2" .* accept'; then
    sudo nft insert rule inet mullvad forward \
      ct state established,related iifname "wg0-mullvad" oifname "virbr2" accept || true
  fi
}

# --- Mullvad unfix (retrait propre de TOUTES nos règles) ---
# --- Mullvad unfix (retrait propre & agressif) ---
mullvad_unfix_forward() {
  local dump handles
  dump="$(sudo nft -a list chain inet mullvad forward 2>/dev/null || true)"
  [ -n "$dump" ] || return 0

  # 1) supprimer TOUTE règle qui mentionne virbr2 (peu importe le sens)
  handles="$(printf '%s\n' "$dump" | grep -E 'iifname "virbr2"|oifname "virbr2"' | awk '{print $NF}')"
  for h in $handles; do
    sudo nft delete rule inet mullvad forward handle "$h" 2>/dev/null || true
  done

  # 2) (ceinture + bretelles) supprimer toute règle wg0<->virbr2 avec ct state established
  dump="$(sudo nft -a list chain inet mullvad forward 2>/dev/null || true)"
  [ -n "$dump" ] || return 0
  handles="$(printf '%s\n' "$dump" | \
    grep -E 'iifname "wg0-mullvad".*oifname "virbr2"|iifname "virbr2".*oifname "wg0-mullvad"' | awk '{print $NF}')"
  for h in $handles; do
    sudo nft delete rule inet mullvad forward handle "$h" 2>/dev/null || true
  done
}


# --- NAT: MASQUERADE 10.88.0.0/24 -> wg0-mullvad (idempotent) ---
nat_up() {
  if ! sudo nft list tables 2>/dev/null | grep -q '^table ip nat$'; then
    sudo nft add table ip nat
  fi
  if ! sudo nft list chain ip nat postrouting 2>/dev/null >/dev/null; then
    sudo nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; }'
  fi
  if ! sudo nft list chain ip nat postrouting 2>/dev/null | \
       grep -q 'oifname "wg0-mullvad" ip saddr 10\.88\.0\.0/24 masquerade'; then
    sudo nft add rule ip nat postrouting oifname "wg0-mullvad" ip saddr 10.88.0.0/24 masquerade
  fi
}

# --- NAT down (retrait propre) ---
nat_down() {
  local H
  H="$(sudo nft -a list chain ip nat postrouting 2>/dev/null | \
      awk '/oifname "wg0-mullvad" ip saddr 10\.88\.0\.0\/24 masquerade/ {print $NF}')"
  [[ -n "${H:-}" ]] && sudo nft delete rule ip nat postrouting handle "$H" || true
}

# --- UFW: règles route + DNS (idempotent & safe) ---
ufw_apply() {
  have ufw || return 0

  sudo ufw route allow in on "${BR_NAME}" out on "${WG_IF}"  from "${SUBNET_V4}" to any || true
  sudo ufw route allow in on "${WG_IF}" out on "${BR_NAME}"  from any to "${SUBNET_V4}" || true

  if ip link show wlp0s20f3 >/dev/null 2>&1; then
    sudo ufw route deny  in on "${BR_NAME}" out on wlp0s20f3 || true
    sudo ufw route deny  in on wlp0s20f3 out on "${BR_NAME}" || true
  fi
  if ip link show enp60s0 >/dev/null 2>&1; then
    sudo ufw route deny  in on "${BR_NAME}" out on enp60s0 || true
    sudo ufw route deny  in on enp60s0 out on "${BR_NAME}" || true
  fi

  sudo ufw allow in on "${BR_NAME}" proto udp from "${SUBNET_V4}" to "${GW_V4}" port 53 || true
  sudo ufw allow in on "${BR_NAME}" proto tcp from "${SUBNET_V4}" to "${GW_V4}" port 53 || true

  sudo ufw reload || true
}

ufw_remove() {
  have ufw || return 0

  sudo ufw route delete allow in on "${BR_NAME}" out on "${WG_IF}"  from "${SUBNET_V4}" to any || true
  sudo ufw route delete allow in on "${WG_IF}" out on "${BR_NAME}"  from any to "${SUBNET_V4}" || true

  if ip link show wlp0s20f3 >/dev/null 2>&1; then
    sudo ufw route delete deny  in on "${BR_NAME}" out on wlp0s20f3 || true
    sudo ufw route delete deny  in on wlp0s20f3 out on "${BR_NAME}" || true
  fi
  if ip link show enp60s0 >/dev/null 2>&1; then
    sudo ufw route delete deny  in on "${BR_NAME}" out on enp60s0 || true
    sudo ufw route delete deny  in on enp60s0 out on "${BR_NAME}" || true
  fi

  sudo ufw delete allow in on "${BR_NAME}" proto udp from "${SUBNET_V4}" to "${GW_V4}" port 53 || true
  sudo ufw delete allow in on "${BR_NAME}" proto tcp from "${SUBNET_V4}" to "${GW_V4}" port 53 || true

  sudo ufw reload || true
}

# --- ip_forward toggle (restaure l'état initial) ---
ipfwd_up() {
  sudo mkdir -p "$STATE_DIR"
  local prev
  prev="$(cat /proc/sys/net/ipv4/ip_forward)"
  echo "$prev" | sudo tee "$IPFWD_FILE" >/dev/null
  sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
}
ipfwd_down() {
  if [[ -f "$IPFWD_FILE" ]]; then
    local prev
    prev="$(cat "$IPFWD_FILE")"
    sudo sysctl -w net.ipv4.ip_forward="$prev" >/dev/null
    sudo rm -f "$IPFWD_FILE"
  else
    sudo sysctl -w net.ipv4.ip_forward=0 >/dev/null
  fi
}

# --- Bridge sanity: forcer vnet* -> virbr2 si non attaché ---
ensure_bridge_ports() {
  if ip link show "${BR_NAME}" | grep -q NO-CARRIER; then
    for p in /sys/class/net/vnet*; do
      [[ -e "$p" ]] || continue
      local ifc; ifc="$(basename "$p")"
      sudo ip link set "$ifc" master "${BR_NAME}" 2>/dev/null || true
      sudo ip link set "$ifc" up 2>/dev/null || true
    done
    sudo ip link set "${BR_NAME}" up 2>/dev/null || true
  fi
}

# --- Commandes ---
cmd_up() {
  require virsh nft systemctl awk sed grep
  [[ -d /sys/class/net/$WG_IF ]] || die "interface $WG_IF introuvable"

  local state
  state="$(cat /sys/class/net/$WG_IF/operstate 2>/dev/null || echo down)"
  case "$state" in up|unknown) : ;; *) die "$WG_IF est $state (Mullvad actif ?)" ;; esac

  /bin/mkdir -p "$STATE_DIR"
  # Nettoyage agressif en cas d'échec
  trap 'nft_down; mullvad_unfix_forward; nat_down; ipfwd_down' INT TERM ERR

  start_daemons
  ipfwd_up

  write_xml
  if net_active;  then vsh net-destroy "$NET_NAME" >/dev/null 2>&1 || true; fi
  if net_defined; then vsh net-undefine "$NET_NAME" >/dev/null 2>&1 || true; fi
  vsh net-define "$XML_FILE"
  vsh net-autostart "$NET_NAME" --disable >/dev/null 2>&1 || true
  vsh net-start "$NET_NAME" >/dev/null 2>&1 || die "échec de démarrage réseau $NET_NAME"

  nft_up
  mullvad_fix_forward
  nat_up
  ufw_apply
  ensure_bridge_ports

  local BR; BR="$(bridge_name)"
  echo "[+] $NET_NAME UP  | bridge=${BR:-?}  | GW=${GW_V4}  | NAT via $WG_IF"
  echo "[i] dnsmasq ${NET_NAME}:"
  sudo grep -E '^(server=|no-resolv)' /var/lib/libvirt/dnsmasq/${NET_NAME}.conf || true
}

cmd_down() {
  ufw_remove
  nft_down
  mullvad_unfix_forward
  nat_down
  if net_active;  then vsh net-destroy "$NET_NAME" >/dev/null 2>&1 || true; fi
  if net_defined; then vsh net-undefine "$NET_NAME" >/dev/null 2>&1 || true; fi
  ipfwd_down
  stop_daemons
  echo "[+] $NET_NAME DOWN (UFW nettoyé, nftables nettoyé, NAT/forward retirés, ip_forward restauré, sockets libvirt stoppés)"
}

cmd_status() {
  if net_defined; then vsh net-info "$NET_NAME" || true; else echo "[i] réseau $NET_NAME non défini"; fi
  echo
  echo "[i] nftables:"
  sudo nft list tables 2>/dev/null | grep -q devnet_guard && echo "table inet devnet_guard" || echo "(aucune table devnet_guard)"
  echo
  echo "[i] ip_forward: $(cat /proc/sys/net/ipv4/ip_forward)"
  echo
  echo "[i] UFW:"
  have ufw && sudo ufw status numbered || true
}

case "${1:-}" in
  up)     cmd_up ;;
  down)   cmd_down ;;
  status) cmd_status ;;
  *) echo "Usage: $0 {up|down|status}"; exit 1 ;;
esac
