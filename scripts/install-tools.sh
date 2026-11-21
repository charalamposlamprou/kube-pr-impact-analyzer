#!/usr/bin/env bash
# Linux CI installer. Versions and checksums come from official release endpoints.
set -euo pipefail
DEST=${1:-"$HOME/.local/bin"}
mkdir -p "$DEST"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
ARCH=$(uname -m)
case "$ARCH" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) exit 1 ;; esac
curl --fail --silent --show-error --location -o helm.tar.gz "https://get.helm.sh/helm-v4.1.1-linux-$ARCH.tar.gz"
curl --fail --silent --show-error --location -o helm.sha "https://get.helm.sh/helm-v4.1.1-linux-$ARCH.tar.gz.sha256sum"
printf '%s  helm.tar.gz\n' "$(cut -d ' ' -f1 helm.sha)" | sha256sum -c -
tar -xzf helm.tar.gz
install -m 0755 "linux-$ARCH/helm" "$DEST/helm"
curl --fail --silent --show-error --location -o kubectl "https://dl.k8s.io/release/v1.35.0/bin/linux/$ARCH/kubectl"
curl --fail --silent --show-error --location -o kubectl.sha "https://dl.k8s.io/release/v1.35.0/bin/linux/$ARCH/kubectl.sha256"
printf '%s  kubectl\n' "$(cat kubectl.sha)" | sha256sum -c -
install -m 0755 kubectl "$DEST/kubectl"
GOBIN="$DEST" go install sigs.k8s.io/kustomize/kustomize/v5@v5.8.1
GOBIN="$DEST" go install sigs.k8s.io/kind@v0.31.0
