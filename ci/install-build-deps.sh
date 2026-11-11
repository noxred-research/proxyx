#!/usr/bin/env bash
# Install the native build dependencies on a hosted Ubuntu runner: CMake and Clang build
# BoringSSL (the session proxy's TLS stack), OpenSSL headers and pkg-config are linked by the
# control plane's Kafka client. protoc is vendored, and librdkafka is built without GSSAPI, so
# neither a protobuf compiler nor SASL headers are needed.
#
# The hosted image usually ships all of them; apt runs only for what is missing, because the
# runner's package mirror sometimes stops resolving for an hour. After a failed attempt the apt
# sources are pointed at archive.ubuntu.com directly and the install is retried.
set -euo pipefail

missing=()
command -v cmake >/dev/null || missing+=(cmake)
command -v clang >/dev/null || missing+=(clang)
command -v pkg-config >/dev/null || missing+=(pkg-config)
dpkg-query -W -f='${Status}' libssl-dev 2>/dev/null | grep -q 'install ok installed' || missing+=(libssl-dev)

if [ "${#missing[@]}" -eq 0 ]; then
  echo "native build dependencies already installed"
  exit 0
fi
echo "installing: ${missing[*]}"

install() {
  sudo apt-get -o Acquire::Retries=5 update \
    && sudo apt-get -o Acquire::Retries=5 install -y "${missing[@]}"
}

for attempt in 1 2 3; do
  if install; then
    exit 0
  fi
  echo "::warning::apt attempt ${attempt} failed; switching to archive.ubuntu.com"
  for sources in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
    if [ -f "$sources" ]; then
      sudo sed -i 's#mirror+file:/etc/apt/apt-mirrors.txt#http://archive.ubuntu.com/ubuntu/#' "$sources"
    fi
  done
  sleep 30
done
exit 1
