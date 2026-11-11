#!/bin/sh
set -eu

# --------------------------------------------------------------------------
# Egress proxy entrypoint
# Starts a VPN tunnel (WireGuard, OpenVPN, or Tailscale), then exposes a
# SOCKS5 proxy through it via microsocks.
#
# Required:
#   VPN_TYPE              "wireguard", "openvpn", or "tailscale"
#
# WireGuard / OpenVPN:
#   VPN_CONFIG            Path to the config file inside the container
#
# Tailscale (needs NET_ADMIN and /dev/net/tun, like the other two):
#   TAILSCALE_AUTH_KEY    Pre-auth key for headless login
#   TAILSCALE_ARGS        Extra flags for `tailscale up` (optional), for example
#                         `--login-server=URL` or `--exit-node=IP`
#
# Optional:
#   SOCKS_PORT            SOCKS5 listen port (default: 1080)
#   SOCKS_USER            SOCKS5 auth username (set together with SOCKS_PASS)
#   SOCKS_PASS            SOCKS5 auth password
#   HEALTH_HOST           Host to ping through the tunnel before serving (default: 1.1.1.1).
#                         Use an address that answers ping only inside the VPN when you can.
#
# The container exits when the tunnel (or microsocks) stops, so the restart policy starts a
# fresh tunnel; it never serves over the container's direct route.
# --------------------------------------------------------------------------

SOCKS_PORT="${SOCKS_PORT:-1080}"
HEALTH_HOST="${HEALTH_HOST:-1.1.1.1}"
WG_IFACE=""
VPN_PID=""
MICROSOCKS_PID=""

die() { echo "FATAL: $1" >&2; exit 1; }

cleanup() {
    echo "Shutting down..."
    [ -n "$MICROSOCKS_PID" ] && kill "$MICROSOCKS_PID" 2>/dev/null || true
    case "$VPN_TYPE" in
        wireguard) wg-quick down "$VPN_CONFIG" 2>/dev/null || true ;;
        openvpn)   [ -n "$VPN_PID" ] && kill "$VPN_PID" 2>/dev/null || true ;;
        tailscale) tailscale down 2>/dev/null || true
                   [ -n "$VPN_PID" ] && kill "$VPN_PID" 2>/dev/null || true ;;
    esac
    echo "Shutdown complete."
}
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 130' INT

# -- Validate ---------------------------------------------------------------

[ -z "${VPN_TYPE:-}" ] && die "VPN_TYPE not set (wireguard|openvpn|tailscale)"

if [ -n "${SOCKS_USER:-}" ] || [ -n "${SOCKS_PASS:-}" ]; then
    [ -n "${SOCKS_USER:-}" ] && [ -n "${SOCKS_PASS:-}" ] || die "set both SOCKS_USER and SOCKS_PASS, or neither"
fi

# -- Start VPN --------------------------------------------------------------

case "$VPN_TYPE" in
    wireguard)
        [ -z "${VPN_CONFIG:-}" ] && die "VPN_CONFIG not set"
        [ -f "$VPN_CONFIG" ] || die "VPN_CONFIG file not found: $VPN_CONFIG"
        echo "Starting WireGuard..."
        wg-quick up "$VPN_CONFIG"
        echo "WireGuard interface is up."
        WG_IFACE=$(basename "$VPN_CONFIG" .conf)
        ;;
    openvpn)
        [ -z "${VPN_CONFIG:-}" ] && die "VPN_CONFIG not set"
        [ -f "$VPN_CONFIG" ] || die "VPN_CONFIG file not found: $VPN_CONFIG"
        echo "Starting OpenVPN..."
        mkdir -p /dev/net && [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
        openvpn --config "$VPN_CONFIG" \
            --script-security 2 \
            --up /etc/openvpn/update-resolv-conf \
            --down /etc/openvpn/update-resolv-conf \
            --daemon --writepid /tmp/openvpn.pid \
            --log /tmp/openvpn.log

        echo "Waiting for OpenVPN tunnel..."
        for i in $(seq 1 30); do
            if ip link show tun0 >/dev/null 2>&1; then
                break
            fi
            if [ "$i" -eq 30 ]; then
                tail -n 20 /tmp/openvpn.log >&2 || true
                die "OpenVPN tunnel did not come up within 30s"
            fi
            sleep 1
        done
        VPN_PID=$(cat /tmp/openvpn.pid)
        echo "OpenVPN tunnel is up (pid=$VPN_PID)."
        ;;
    tailscale)
        [ -z "${TAILSCALE_AUTH_KEY:-}" ] && die "TAILSCALE_AUTH_KEY not set"
        # Kernel TUN, not userspace networking: microsocks dials through the container's own
        # routes, so only a real interface carries its connections into the tailnet (and to an
        # exit node), and only a real interface makes the connectivity check below meaningful.
        mkdir -p /dev/net && [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
        echo "Starting Tailscale daemon..."
        tailscaled --state=/tmp/tailscale.state &
        VPN_PID=$!
        for i in $(seq 1 10); do
            [ -S /var/run/tailscale/tailscaled.sock ] && break
            [ "$i" -eq 10 ] && die "tailscaled did not start within 10s"
            sleep 1
        done

        echo "Bringing Tailscale up..."
        # The timeout stops an unreachable control plane from hanging the container. A later
        # --timeout in TAILSCALE_ARGS overrides it.
        # shellcheck disable=SC2086
        tailscale up --authkey="$TAILSCALE_AUTH_KEY" --accept-routes --timeout=60s ${TAILSCALE_ARGS:-}
        echo "Tailscale is up."
        ;;
    *)
        die "Unknown VPN_TYPE: $VPN_TYPE (expected wireguard|openvpn|tailscale)"
        ;;
esac

# -- Verify connectivity through tunnel -------------------------------------

echo "Verifying tunnel connectivity to $HEALTH_HOST..."
for i in $(seq 1 10); do
    if ping -c1 -W2 "$HEALTH_HOST" >/dev/null 2>&1; then
        echo "Tunnel connectivity verified."
        break
    fi
    [ "$i" -eq 10 ] && die "No connectivity through tunnel after 10 attempts"
    sleep 1
done

# -- Start SOCKS5 proxy ----------------------------------------------------

MICROSOCKS_ARGS="-p $SOCKS_PORT -b 0.0.0.0"
if [ -n "${SOCKS_USER:-}" ] && [ -n "${SOCKS_PASS:-}" ]; then
    MICROSOCKS_ARGS="$MICROSOCKS_ARGS -u $SOCKS_USER -P $SOCKS_PASS"
fi

echo "Starting microsocks on 0.0.0.0:$SOCKS_PORT..."
# shellcheck disable=SC2086
microsocks $MICROSOCKS_ARGS &
MICROSOCKS_PID=$!

echo "Egress proxy ready (socks5://0.0.0.0:$SOCKS_PORT)"

# -- Supervise --------------------------------------------------------------
# Once the tunnel is gone, microsocks would keep answering over the container's own route and
# clients would leave from the host's address instead of the VPN exit. Stop instead, so the
# restart policy brings up a fresh tunnel. A signal runs the trap, which exits.

# A dead child stays a zombie until reaped, and `kill -0` still succeeds on a zombie.
alive() {
    case "$(cat "/proc/$1/stat" 2>/dev/null)" in
        ""|*") Z "*) return 1 ;;
    esac
    return 0
}

tunnel_up() {
    case "$VPN_TYPE" in
        wireguard) ip link show dev "$WG_IFACE" >/dev/null 2>&1 ;;
        *)         alive "$VPN_PID" ;;
    esac
}

while :; do
    alive "$MICROSOCKS_PID" || { cleanup; die "microsocks exited"; }
    tunnel_up || { cleanup; die "VPN tunnel is gone"; }
    sleep 2 &
    wait $!
done
