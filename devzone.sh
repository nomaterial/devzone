#!/usr/bin/env bash
sudo -v || exit 1
set -euo pipefail

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

have()    { command -v "$1" >/dev/null 2>&1; }
die()     { echo "[-] $*" >&2; exit 1; }
require() { for c in "$@"; do have "$c" || die "commande manquante: $c"; done; }
vsh()     { LC_ALL=C sudo virsh -c "$URI" "$@"; }

net_exists()  { vsh net-list --all 2>/dev/null | awk '{print $1}' | grep -qx "$NET_NAME"; }
net_active()  { vsh net-info "$NET_NAME" 2>/dev/null | awk -F': *' '/^Active:/ {print tolower($2)}' | grep -q yes; }
bridge_name() { vsh net-info "$NET_NAME" 2>/dev/null | awk -F': *' '/^Bridge:/ {print $2}'; }

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

nft_up() {
  sudo nft -f - <<'NFT'
table inet devnet_guard {
  chain forward {
    type filter hook forward priority -200;
    policy drop;
    ct state established,related accept
    iifname { "virbr2", "vnet*" } ip saddr != 10.88.0.0/24 drop
    ip saddr 10.88.0.0/24 ip daddr 10.88.0.1 udp dport {53,67} accept
    ip saddr 10.88.0.1 ip daddr 10.88.0.0/24 udp sport {53,67} accept
    ip saddr 10.88.0.0/24 ip daddr 10.88.0.1 tcp dport 53 accept
    ip saddr 10.88.0.1 ip daddr 10.88.0.0/24 tcp sport 53 accept
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
  sudo nft list tables 2>/dev/null | grep -q "^table inet devnet_guard$" && sudo nft delete table inet devnet_guard || true
}

mullvad_fix_forward() {
  have nft || return 0
  sudo nft insert rule inet mullvad forward ip saddr 10.88.0.0/24 iifname "virbr2" oifname "wg0-mullvad" accept 2>/dev/null || true
  sudo nft insert rule inet mullvad forward ct state established,related iifname "wg0-mullvad" oifname "virbr2" accept 2>/dev/null || true
}

mullvad_unfix_forward() {
  echo "[i] nettoyage règles mullvad..."
  
  # Vérifier si la table mullvad existe
  if ! sudo nft list tables 2>/dev/null | grep -q '^table inet mullvad$'; then
    echo "[i] table mullvad absente, rien à nettoyer"
    return 0
  fi
  
  # Vérifier si la chaîne forward existe
  if ! sudo nft list chain inet mullvad forward 2>/dev/null >/dev/null; then
    echo "[i] chaîne mullvad forward absente, rien à nettoyer"
    return 0
  fi
  
  # Suppression simple et directe
  echo "[i] suppression règles mullvad virbr2..."
  sudo nft delete rule inet mullvad forward iifname "virbr2" 2>/dev/null || true
  sudo nft delete rule inet mullvad forward oifname "virbr2" 2>/dev/null || true
  sudo nft delete rule inet mullvad forward iifname "wg0-mullvad" oifname "virbr2" 2>/dev/null || true
  sudo nft delete rule inet mullvad forward iifname "virbr2" oifname "wg0-mullvad" 2>/dev/null || true
  
  echo "[i] nettoyage mullvad terminé"
}

nat_up() {
  if ! sudo nft list tables 2>/dev/null | grep -q '^table ip nat$'; then
    sudo nft add table ip nat
  fi
  if ! sudo nft list chain ip nat postrouting 2>/dev/null >/dev/null; then
    sudo nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; }'
  fi
  if ! sudo nft list chain ip nat postrouting 2>/dev/null | grep -q 'oifname "wg0-mullvad" ip saddr 10\.88\.0\.0/24 masquerade'; then
    sudo nft add rule ip nat postrouting oifname "wg0-mullvad" ip saddr 10.88.0.0/24 masquerade
  fi
}

nat_down() {
  local dump handles
  dump="$(sudo nft -a list chain ip nat postrouting 2>/dev/null || true)"
  [ -n "$dump" ] || return 0
  handles="$(printf '%s\n' "$dump" | awk '/(oif(name)? "wg0-mullvad").*ip saddr 10\.88\.0\.0\/24 .* masquerade/ {print $NF}')"
  for h in $handles; do sudo nft delete rule ip nat postrouting handle "$h" 2>/dev/null || true; done
}

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

force_cleanup_bridge() {
  echo "[i] nettoyage forcé du bridge ${BR_NAME}..."
  
  # Détacher tous les ports vnet du bridge
  for p in /sys/class/net/vnet*; do
    [[ -e "$p" ]] || continue
    local port="$(basename "$p")"
    if ip link show "$port" 2>/dev/null | grep -q "master ${BR_NAME}"; then
      echo "[i] détachement du port $port du bridge ${BR_NAME}"
      sudo ip link set "$port" nomaster 2>/dev/null || true
      sudo ip link set "$port" down 2>/dev/null || true
    fi
  done
  
  # Supprimer le bridge s'il existe encore
  if ip link show "${BR_NAME}" >/dev/null 2>&1; then
    echo "[i] suppression du bridge ${BR_NAME}..."
    sudo ip addr flush dev "${BR_NAME}" 2>/dev/null || true
    sudo ip link set "${BR_NAME}" down 2>/dev/null || true
    
    # Essayer plusieurs méthodes de suppression
    sudo ip link delete "${BR_NAME}" 2>/dev/null || {
      echo "[!] échec suppression normale, tentative forcée..."
      sudo brctl delbr "${BR_NAME}" 2>/dev/null || true
      sudo ip link delete "${BR_NAME}" 2>/dev/null || true
    }
    
    # Vérifier que le bridge est vraiment supprimé
    if ip link show "${BR_NAME}" >/dev/null 2>&1; then
      echo "[!] WARNING: bridge ${BR_NAME} persiste encore"
    else
      echo "[+] bridge ${BR_NAME} supprimé avec succès"
    fi
  else
    echo "[+] bridge ${BR_NAME} déjà absent"
  fi
}

force_cleanup_all() {
  echo "[!] NETTOYAGE COMPLET - suppression forcée de $NET_NAME"
  
  # Nettoyer les règles nftables
  echo "[i] nettoyage nftables..."
  sudo nft list tables 2>/dev/null | grep -q "^table inet devnet_guard$" && sudo nft delete table inet devnet_guard || true
  sudo nft list tables 2>/dev/null | grep -q '^table ip nat$' && {
    dump="$(sudo nft -a list chain ip nat postrouting 2>/dev/null || true)"
    handles="$(printf '%s\n' "$dump" | awk '/(oif(name)? "wg0-mullvad").*ip saddr 10\.88\.0\.0\/24 .* masquerade/ {print $NF}')"
    for h in $handles; do sudo nft delete rule ip nat postrouting handle "$h" 2>/dev/null || true; done
  }
  
  # Nettoyer les règles UFW
  echo "[i] nettoyage UFW..."
  sudo ufw route delete allow in on "${BR_NAME}" out on "wg0-mullvad" from "10.88.0.0/24" to any 2>/dev/null || true
  sudo ufw route delete allow in on "wg0-mullvad" out on "${BR_NAME}" from any to "10.88.0.0/24" 2>/dev/null || true
  sudo ufw delete allow in on "${BR_NAME}" proto udp from "10.88.0.0/24" to "10.88.0.1" port 53 2>/dev/null || true
  sudo ufw delete allow in on "${BR_NAME}" proto tcp from "10.88.0.0/24" to "10.88.0.1" port 53 2>/dev/null || true
  sudo ufw reload 2>/dev/null || true
  
  # Tuer dnsmasq
  echo "[i] arrêt dnsmasq..."
  sudo pkill -f "dnsmasq.*${NET_NAME}\.conf" 2>/dev/null || true
  
  # Supprimer les fichiers de configuration
  echo "[i] suppression fichiers config..."
  sudo rm -f "/etc/libvirt/qemu/networks/${NET_NAME}.xml" \
            "/etc/libvirt/qemu/networks/autostart/${NET_NAME}.xml" \
            "/var/lib/libvirt/dnsmasq/${NET_NAME}.conf" \
            "/var/lib/libvirt/dnsmasq/${NET_NAME}.status" 2>/dev/null || true
  
  # Démarrer libvirt si possible
  echo "[i] démarrage libvirt..."
  sudo systemctl start libvirtd.socket virtqemud.socket virtnetworkd.socket 2>/dev/null || true
  sleep 1
  
  # Supprimer le réseau libvirt
  echo "[i] suppression réseau libvirt..."
  sudo virsh -c qemu:///system net-destroy "$NET_NAME" 2>/dev/null || true
  sudo virsh -c qemu:///system net-undefine "$NET_NAME" 2>/dev/null || true
  
  # Nettoyer le bridge
  force_cleanup_bridge
  
  # Redémarrer virtnetworkd pour être sûr
  sudo systemctl try-restart virtnetworkd.service 2>/dev/null || true
  
  echo "[+] nettoyage complet terminé"
}

cmd_up() {
  require virsh nft systemctl awk sed grep
  [[ -d /sys/class/net/$WG_IF ]] || die "interface $WG_IF introuvable"
  local state
  state="$(cat /sys/class/net/$WG_IF/operstate 2>/dev/null || echo down)"
  case "$state" in up|unknown) : ;; *) die "$WG_IF est $state (Mullvad actif ?)" ;; esac
  /bin/mkdir -p "$STATE_DIR"
  trap 'nft_down; mullvad_unfix_forward; nat_down; ipfwd_down' INT TERM ERR
  start_daemons
  ipfwd_up
  write_xml
  if net_active;  then vsh net-destroy "$NET_NAME" >/dev/null 2>&1 || true; fi
  if net_exists;  then vsh net-undefine "$NET_NAME" >/dev/null 2>&1 || true; fi
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
  echo "[i] début cmd_down()"
  
  # Essayer de démarrer les daemons, sinon continuer en mode nettoyage forcé
  if ! start_daemons; then
    echo "[!] daemons libvirt indisponibles, nettoyage forcé uniquement"
    force_cleanup_all
    ipfwd_down
    echo "[+] $NET_NAME DOWN (nettoyage forcé)"
    return 0
  fi
  
  echo "[i] daemons libvirt démarrés, début nettoyage normal"
  echo "[i] nettoyage UFW..."
  ufw_remove
  echo "[i] nettoyage nftables..."
  nft_down
  echo "[i] nettoyage mullvad..."
  mullvad_unfix_forward
  echo "[i] nettoyage NAT..."
  nat_down
  # Détruire et supprimer le réseau libvirt
  echo "[i] vérification réseau libvirt..."
  if net_exists; then
    echo "[i] réseau $NET_NAME trouvé, suppression..."
    vsh net-destroy   "$NET_NAME"  >/dev/null 2>&1 || true
    vsh net-autostart "$NET_NAME" --disable >/dev/null 2>&1 || true
    vsh net-undefine  "$NET_NAME"  >/dev/null 2>&1 || true
  else
    echo "[i] réseau $NET_NAME non trouvé"
  fi
  
  # Attendre que le réseau soit supprimé (maximum 3 secondes)
  echo "[i] attente suppression réseau..."
  for _ in {1..30}; do
    net_exists || break
    sleep 0.1
  done
  
  # Forcer la suppression même si le réseau existe encore
  if net_exists; then
    echo "[!] réseau $NET_NAME encore présent, suppression forcée..."
    vsh net-destroy   "$NET_NAME"  >/dev/null 2>&1 || true
    vsh net-undefine  "$NET_NAME"  >/dev/null 2>&1 || true
    sleep 0.5  # Laisser le temps à libvirt de traiter
  else
    echo "[i] réseau $NET_NAME supprimé avec succès"
  fi
  echo "[i] suppression fichiers de configuration..."
  sudo rm -f \
    "/etc/libvirt/qemu/networks/${NET_NAME}.xml" \
    "/etc/libvirt/qemu/networks/autostart/${NET_NAME}.xml" \
    "/var/lib/libvirt/dnsmasq/${NET_NAME}.conf" \
    "/var/lib/libvirt/dnsmasq/${NET_NAME}.status" 2>/dev/null || true
  sudo systemctl try-restart virtnetworkd.service 2>/dev/null || true
  
  # Attendre que libvirt supprime le bridge automatiquement (maximum 2 secondes)
  echo "[i] attente suppression bridge par libvirt..."
  for _ in {1..20}; do
    ip link show "${BR_NAME}" >/dev/null 2>&1 || { echo "[+] ${BR_NAME} retiré par libvirt"; break; }
    sleep 0.1
  done
  
  # Toujours forcer le nettoyage complet pour être sûr
  echo "[i] début nettoyage final..."
  force_cleanup_all
  ipfwd_down
  [ -z "${KEEP_DAEMONS:-}" ] && stop_daemons || true
  echo "[+] $NET_NAME DOWN (nettoyé)"
}

cmd_status() {
  start_daemons
  if net_exists; then vsh net-info "$NET_NAME" || true; else echo "[i] réseau $NET_NAME non défini"; fi
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
  up)       cmd_up ;;
  down)     cmd_down ;;
  status)   cmd_status ;;
  cleanup)  force_cleanup_all; ipfwd_down; echo "[+] nettoyage complet terminé" ;;
  *) echo "Usage: $0 {up|down|status|cleanup}"; exit 1 ;;
esac
