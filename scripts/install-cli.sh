#!/usr/bin/env sh
# Installs the SocialName local CLI from a published GitHub Release.
#
# The script downloads one archive plus the release checksum file, verifies the
# archive against it, and unpacks the binary and its site-rule pack into a
# user-owned directory. It never needs administrator rights, never touches
# system directories, and never contacts a SocialName service: the local CLI
# defaults to local execution with sync=never.
#
#   curl -fsSL https://raw.githubusercontent.com/yhay81/socialname/main/scripts/install-cli.sh | sh
#
# Environment:
#   SOCIALNAME_VERSION   release tag to install (default: latest)
#   SOCIALNAME_PREFIX    install root (default: $HOME/.socialname)

set -eu

REPOSITORY="yhay81/socialname"
PREFIX="${SOCIALNAME_PREFIX:-$HOME/.socialname}"
VERSION="${SOCIALNAME_VERSION:-latest}"

fail() {
    printf 'socialname-install: %s\n' "$1" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "required command '$1' was not found"
}

need uname
need tar
need mktemp
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO "$2" "$1"; }
else
    fail "either curl or wget is required"
fi

case "$(uname -s)" in
    Darwin) platform=apple-darwin ;;
    Linux) platform=unknown-linux-gnu ;;
    *) fail "unsupported operating system '$(uname -s)'; see docs/installation.md" ;;
esac

case "$(uname -m)" in
    x86_64 | amd64) architecture=x86_64 ;;
    arm64 | aarch64) architecture=aarch64 ;;
    *) fail "unsupported architecture '$(uname -m)'" ;;
esac

target="${architecture}-${platform}"
archive="socialname-cli-${target}.tar.gz"

if [ "$VERSION" = latest ]; then
    base="https://github.com/${REPOSITORY}/releases/latest/download"
else
    base="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
fi

workspace="$(mktemp -d)"
cleanup() { rm -rf "$workspace"; }
trap cleanup EXIT INT TERM

printf 'socialname-install: downloading %s\n' "$archive"
fetch "${base}/${archive}" "${workspace}/${archive}" \
    || fail "could not download ${base}/${archive}"
fetch "${base}/SHA256SUMS.txt" "${workspace}/SHA256SUMS.txt" \
    || fail "could not download the release checksum file"

if command -v sha256sum >/dev/null 2>&1; then
    computed="$(sha256sum "${workspace}/${archive}" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
    computed="$(shasum -a 256 "${workspace}/${archive}" | cut -d' ' -f1)"
else
    fail "either sha256sum or shasum is required to verify the download"
fi
expected="$(grep " \{1,2\}\*\{0,1\}${archive}\$" "${workspace}/SHA256SUMS.txt" | cut -d' ' -f1 | head -n 1)"
[ -n "$expected" ] || fail "the release checksum file does not list ${archive}"
[ "$computed" = "$expected" ] || fail "checksum mismatch for ${archive}; refusing to install"
printf 'socialname-install: checksum verified\n'

tar -xzf "${workspace}/${archive}" -C "$workspace"
unpacked="${workspace}/socialname-${target}"
[ -x "${unpacked}/socialname" ] || fail "the archive did not contain the expected binary"

mkdir -p "${PREFIX}/bin"
rm -rf "${PREFIX}/rules"
cp "${unpacked}/socialname" "${PREFIX}/bin/socialname"
chmod +x "${PREFIX}/bin/socialname"
cp -R "${unpacked}/rules" "${PREFIX}/rules"

printf 'socialname-install: installed %s\n' "${PREFIX}/bin/socialname"
case ":${PATH}:" in
    *":${PREFIX}/bin:"*) ;;
    *)
        printf 'socialname-install: add it to PATH, for example\n'
        printf '  export PATH="%s/bin:$PATH"\n' "$PREFIX"
        ;;
esac
printf 'socialname-install: try\n'
printf '  socialname rules list --rules-dir %s/rules/sites\n' "$PREFIX"
printf '  socialname search octocat --site github --rules-dir %s/rules/sites --allow-disabled\n' "$PREFIX"
