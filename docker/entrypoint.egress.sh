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
# Tailscale:
#   TAILSCALE_AUTH_KEY    Pre-auth key for headless login
#   TAILSCALE_ARGS        Extra flags for `tailscale up` (optional)
#
# Optional:
#   SOCKS_PORT            SOCKS5 listen port (default: 1080)
#   SOCKS_USER            SOCKS5 auth username
#   SOCKS_PASS            SOCKS5 auth password
#   HEALTH_HOST           Host to ping for health check (default: 1.1.1.1)
# --------------------------------------------------------------------------

SOCKS_PORT="${SOCKS_PORT:-1080}"
HEALTH_HOST="${HEALTH_HOST:-1.1.1.1}"
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
trap cleanup TERM INT

# -- Validate ---------------------------------------------------------------

[ -z "${VPN_TYPE:-}" ] && die "VPN_TYPE not set (wireguard|openvpn|tailscale)"

# -- Start VPN --------------------------------------------------------------

case "$VPN_TYPE" in
    wireguard)
        [ -z "${VPN_CONFIG:-}" ] && die "VPN_CONFIG not set"
        [ -f "$VPN_CONFIG" ] || die "VPN_CONFIG file not found: $VPN_CONFIG"
        echo "Starting WireGuard..."
        wg-quick up "$VPN_CONFIG"
        echo "WireGuard interface is up."
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
            [ "$i" -eq 30 ] && die "OpenVPN tunnel did not come up within 30s"
            sleep 1
        done
        VPN_PID=$(cat /tmp/openvpn.pid)
        echo "OpenVPN tunnel is up (pid=$VPN_PID)."
        ;;
    tailscale)
        [ -z "${TAILSCALE_AUTH_KEY:-}" ] && die "TAILSCALE_AUTH_KEY not set"
        echo "Starting Tailscale daemon..."
        tailscaled --state=/tmp/tailscale.state --tun=userspace-networking &
        VPN_PID=$!
        sleep 2

        echo "Bringing Tailscale up..."
        # shellcheck disable=SC2086
        tailscale up --authkey="$TAILSCALE_AUTH_KEY" --accept-routes ${TAILSCALE_ARGS:-}
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

# -- Wait for child processes -----------------------------------------------
# Block until microsocks exits or we get a signal (handled by trap).
wait "$MICROSOCKS_PID"
