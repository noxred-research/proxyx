#!/usr/bin/env bash
# Install the native build dependencies (BoringSSL, librdkafka, protobuf) on a hosted
# Ubuntu runner. The runner's package mirror sometimes stops resolving for an hour; after a
# failed attempt the apt sources are pointed at archive.ubuntu.com directly and retried.
set -euo pipefail

packages=(cmake clang protobuf-compiler libssl-dev libsasl2-dev pkg-config)

install() {
  sudo apt-get -o Acquire::Retries=5 update \
    && sudo apt-get -o Acquire::Retries=5 install -y "${packages[@]}"
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
