#!/usr/bin/env bash
# Renders the Homebrew and WinGet manifests for one release.
#
#   scripts/render-package-manifests.sh <version> <artifact-dir> <output-dir>
#
# Every checksum is read from the artifact directory's SHA256SUMS.txt, which
# the release job computes from the artifacts it is about to publish. A
# missing artifact, a missing digest, or a placeholder that survives
# substitution is a hard failure, so a manifest can never claim a digest that
# was not computed from the file it installs.

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <version> <artifact-dir> <output-dir>" >&2
    exit 2
fi

version="$1"
artifacts="$2"
output="$3"
templates="$(cd "$(dirname "$0")/../packaging" && pwd)"
checksums="${artifacts}/SHA256SUMS.txt"

[ -f "$checksums" ] || {
    echo "render-package-manifests: ${checksums} is missing" >&2
    exit 1
}

# Rejects a version that would produce an invalid manifest or an unexpected
# download URL.
case "$version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "render-package-manifests: '${version}' is not a x.y.z version" >&2
        exit 1
        ;;
esac

digest_of() {
    local file="$1"
    local found
    found="$(awk -v name="$file" '$2 == name || $2 == "*" name { print $1; exit }' "$checksums")"
    if [ -z "$found" ]; then
        echo "render-package-manifests: ${checksums} has no digest for ${file}" >&2
        exit 1
    fi
    printf '%s' "$found"
}

setup_exe="SocialName_${version}_x64-setup.exe"
universal_dmg="SocialName_${version}_universal.dmg"

sha_macos_arm="$(digest_of socialname-cli-aarch64-apple-darwin.tar.gz)"
sha_macos_intel="$(digest_of socialname-cli-x86_64-apple-darwin.tar.gz)"
sha_linux_arm="$(digest_of socialname-cli-aarch64-unknown-linux-gnu.tar.gz)"
sha_linux_intel="$(digest_of socialname-cli-x86_64-unknown-linux-gnu.tar.gz)"
sha_setup="$(digest_of "$setup_exe")"
sha_dmg="$(digest_of "$universal_dmg")"
release_date="$(date -u +%Y-%m-%d)"

mkdir -p "${output}/homebrew" "${output}/winget"

render() {
    local source="$1"
    local destination="$2"
    sed \
        -e "s/__VERSION__/${version}/g" \
        -e "s/__RELEASE_DATE__/${release_date}/g" \
        -e "s/__SHA256_AARCH64_APPLE_DARWIN__/${sha_macos_arm}/g" \
        -e "s/__SHA256_X86_64_APPLE_DARWIN__/${sha_macos_intel}/g" \
        -e "s/__SHA256_AARCH64_UNKNOWN_LINUX_GNU__/${sha_linux_arm}/g" \
        -e "s/__SHA256_X86_64_UNKNOWN_LINUX_GNU__/${sha_linux_intel}/g" \
        -e "s/__SHA256_WINDOWS_SETUP__/${sha_setup}/g" \
        -e "s/__SHA256_UNIVERSAL_DMG__/${sha_dmg}/g" \
        "$source" > "$destination"
    if grep -q '__[A-Z0-9_]\{3,\}__' "$destination"; then
        echo "render-package-manifests: ${destination} still has a placeholder" >&2
        grep -n '__[A-Z0-9_]\{3,\}__' "$destination" >&2
        exit 1
    fi
}

render "${templates}/homebrew/socialname.rb.template" "${output}/homebrew/socialname.rb"
render "${templates}/homebrew/socialname-desktop.rb.template" \
    "${output}/homebrew/socialname-desktop.rb"
for manifest in \
    yhay81.SocialName.installer.yaml \
    yhay81.SocialName.locale.en-US.yaml \
    yhay81.SocialName.yaml; do
    render "${templates}/winget/${manifest}.template" "${output}/winget/${manifest}"
done

echo "render-package-manifests: rendered manifests for ${version} into ${output}"
