#!/bin/sh
# Installs the rootwalk release binary for this machine into ~/.local/bin.
#
#   curl -fsSL https://raw.githubusercontent.com/Rakshit-gen/rootwalk/main/scripts/install.sh | sh
#
# ROOTWALK_VERSION picks a version (default: the latest release) and
# ROOTWALK_BIN_DIR the directory (default: $HOME/.local/bin).
set -eu

repo=Rakshit-gen/rootwalk
version=${ROOTWALK_VERSION:-latest}
bin_dir=${ROOTWALK_BIN_DIR:-$HOME/.local/bin}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "rootwalk is built for Linux and macOS, not $(uname -s)" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "rootwalk is built for amd64 and arm64, not $(uname -m)" ;;
esac

if [ "$version" = latest ]; then
	version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
	[ -n "$version" ] || die "couldn't find the latest release; set ROOTWALK_VERSION"
fi
case "$version" in v*) ;; *) version=v$version ;; esac

archive="rootwalk_${version#v}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf 'downloading %s\n' "$archive"
curl -fsSL "$base/$archive" -o "$tmp/$archive" || die "download failed: $base/$archive"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || die "couldn't download checksums.txt"

want=$(awk -v f="$archive" '$2 == f {print $1}' "$tmp/checksums.txt")
if command -v sha256sum >/dev/null; then
	got=$(sha256sum "$tmp/$archive" | awk '{print $1}')
else
	got=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')
fi
[ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $archive"

tar -xzf "$tmp/$archive" -C "$tmp" rootwalk
mkdir -p "$bin_dir"
mv "$tmp/rootwalk" "$bin_dir/rootwalk"
chmod +x "$bin_dir/rootwalk"
printf 'installed %s to %s\n' "$("$bin_dir/rootwalk" -version)" "$bin_dir/rootwalk"

case ":$PATH:" in
*":$bin_dir:"*) ;;
*) printf '%s is not on your PATH; add it in your shell profile:\n  export PATH="%s:$PATH"\n' "$bin_dir" "$bin_dir" ;;
esac
