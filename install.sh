#!/bin/sh
# Install the published, platform-specific Nuitka binary without Python or uv.
#
#   curl -fsSL <release-url>/install.sh | sh
#   ./install.sh [VERSION] [--prefix DIRECTORY] [--force]
#
# Verification is two-layered: a sha256 checksum catches transit corruption, and an
# openssl RSA signature over the binary is the actual trust control -- an attacker who
# can replace the binary can replace its checksum file too, but cannot forge a
# signature without the private key. There is no flag to skip the signature check.
set -eu

# ─────────────────────────────────────────────────────────────────────────────────
# MOCK / TBD -- where a release actually lives. None of this is final; every value
# below is a placeholder, overridable via env so the rest of the script can be
# written and exercised before the real hosting is decided. Once it is, update the
# defaults here -- this is the one place they live.
# ─────────────────────────────────────────────────────────────────────────────────
REPOSITORY="${CWPILOT_REPOSITORY:-Clockwork-Pilot/cwpilot-release}"
BASE_URL="${CWPILOT_RELEASE_BASE_URL:-https://github.com/${REPOSITORY}/releases}"
PREFIX="${CWPILOT_INSTALL_PREFIX:-${HOME:-}/.local/bin}"
VERSIONS_DIR="${CWPILOT_VERSIONS_DIR:-${HOME:-}/.local/share/cwpilot-versions}"
TIMEOUT_SECONDS="${CWPILOT_INSTALL_TIMEOUT:-60}"
VERSION="${CWPILOT_VERSION:-}"
FORCE=0

# The RSA public key releases are signed with, as PEM (SubjectPublicKeyInfo). Embedded
# literally -- not read from a sibling file -- because this script must work piped
# through `curl | sh`, where there is no checkout to read a file out of. This is the
# place to put your public key: paste the contents of signing.pub below, replacing this
# block, and keep signing.pub at the repo root in sync so the two never drift apart.
# Rotate by editing both at once.
PUBKEY_PEM='-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn4GrxtJher6IBoMoq7od
JbiZ5ACLJvEKabwjz+XJFGzIhQUgYy/B2TbX0KuiLRxHnMn7pbRBa68yAB7CL5C5
eZiZLV6VwG9yayhOxXVCOsb3kBliJITkXYZLiPJ3yMvwarFm9ZuYbvN+Pfjrhy6s
yfYgnoTdTYoORTw3OJO/HU0yZEkNSe5tJ1CRws6sXBEJ9ylb1NZfewDGxRAnxtvg
eooPhbtAzBgJ9YpqQi4VLMXPRrTymypm6oF6bS8c+L54VDk37Xr6sTzX/nlq0EMR
Bpy/KGtJZQgceyx5qe2DIu2tvso2V7tRKhtoLhzLwP5IfXvTTeICM3zIDZTkUrIZ
98Vj0yW9rjsmGLIc0j5PTE8iS2jmI2VeVwsNb2/8SO0SHhlJ1YRnm442l26+VtAh
6io7TUyzfQ7mmVAAYMTjd/uq8lswut1Gv/eQ5AH+VJ4QSYIEMFRL8TnUsQf3qVXj
TL2lPz1k7GZlGgZMkt8QT0Gm10WCVr6yH6YpdXOeVIydLavEOXxf74PaYeO1zWvZ
9O7pCTR7ETQhN+50Xwpq2hEe+67eOwlYJ7yl5FQPtNdZqk0wXQs6b8Qy2n09UbUH
g9q9iIgMMKoomDGuhy7r4y0Ua0lFFh9QpA8/9k3/90+6z05IfP97hZKyk7po/Y41
vOipVXWeyt0DjfsGpSmBi/MCAwEAAQ==
-----END PUBLIC KEY-----'

usage() {
    cat <<EOF
Usage: install.sh [VERSION] [--prefix DIRECTORY] [--force]

Installs cwpilot from the Clockwork-Pilot release assets.

VERSION is a positional release tag such as v0.0.1 (a bare 0.0.1 is also accepted
and normalized to the v-prefixed tag). It defaults to "latest" when omitted (or
CWPILOT_VERSION is unset), which resolves to whatever release GitHub currently
marks latest -- re-resolved on every run, not cached under its own alias.

Re-running updates the stable link; --force re-downloads the requested version.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            [ "$#" -ge 2 ] || { echo "error: --prefix needs a value" >&2; exit 2; }
            PREFIX="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        --*) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) VERSION="$1"; shift ;;
    esac
done

system="$(uname -s)"
system="$(printf '%s' "$system" | tr '[:upper:]' '[:lower:]')"
case "$system" in
    linux|darwin) ;;
    *) echo "error: unsupported OS: $system" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64)  arch=x86_64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "error: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

PLATFORM="${system}-${arch}"
ASSET="cwpilot-${PLATFORM}"

tmpdir=""
cache_tmp=""
link_tmp=""
cleanup() {
    [ -z "$tmpdir" ] || rm -rf "$tmpdir"
    [ -z "$cache_tmp" ] || rm -f "$cache_tmp"
    [ -z "$link_tmp" ] || rm -f "$link_tmp"
}
trap cleanup EXIT INT TERM

ensure_tmpdir() {
    [ -n "$tmpdir" ] || tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/cwpilot-install.XXXXXX")"
}

# Wraps curl with a message that names what failed to download and why, instead of
# leaving the bare "curl: (22) The requested URL returned error: 404" to explain
# itself -- that error alone doesn't say whether it was the binary, the signature,
# or the release metadata that 404'd, or against which URL.
fetch() {
    description="$1"; url="$2"; out="$3"; shift 3
    if ! curl --fail --silent --show-error --location --max-time "$TIMEOUT_SECONDS" \
            "$@" "$url" -o "$out"; then
        echo "error: failed to download ${description} from ${url}" >&2
        exit 1
    fi
}

# ── Version: resolve "latest" to the concrete tag it currently points at ────────
# "latest" is a moving alias, not a cache key. Caching it under a directory literally
# named "latest" would mean a later `install.sh` with no args never notices a new
# release without --force, and would leave the same release duplicated on disk once
# it's also installed by its explicit tag (e.g. both versions/latest/ and
# versions/1.1.1/). So the alias is always resolved against the API first -- a small
# JSON request, not the binary -- and everything downstream (cache directory, digest
# lookup, download URL) uses the resolved tag, exactly like an explicit version.
prefetched_metadata=""
if [ -z "$VERSION" ] || [ "$VERSION" = latest ]; then
    command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
    ensure_tmpdir
    prefetched_metadata="${tmpdir}/release.json"
    fetch "latest release metadata" "https://api.github.com/repos/${REPOSITORY}/releases/latest" \
        "$prefetched_metadata" -H "Accept: application/vnd.github+json"

    # Same pretty-printed-JSON, no-parser-needed approach as extract_digest below:
    # "tag_name" appears once, at the top level of the release object.
    tag="$(awk '
        /"tag_name":/ {
            line = $0
            sub(/^[^"]*"tag_name": *"/, "", line)
            sub(/".*$/, "", line)
            print line
            exit
        }
    ' "$prefetched_metadata")"
    [ -n "$tag" ] || {
        echo "error: no tag_name found in latest release metadata" >&2
        exit 1
    }
    VERSION="$tag"
fi

# This repo's tags are v-prefixed (v1.0.0), not bare versions -- and GitHub's tag
# and download URLs need the literal tag, so a version typed without the "v" (e.g.
# "1.0.0") is normalized to match it. Resolved-from-latest and explicitly-typed
# versions both go through this, so "latest" and "v1.0.0"/"1.0.0" converge on the
# exact same string and therefore the same cache directory -- no duplicate installs
# of the same release under two different-looking names.
case "$VERSION" in
    v*) ;;
    *) VERSION="v${VERSION}" ;;
esac

# VERSION becomes a directory name below. Reject path traversal rather than allowing
# an option (or an API response) intended to select a release to escape the install
# cache.
case "$VERSION" in
    v|*/*) echo "error: invalid version: ${VERSION}" >&2; exit 2 ;;
esac

RELEASE_URL="${BASE_URL}/download/${VERSION}"
API_URL="https://api.github.com/repos/${REPOSITORY}/releases/tags/${VERSION}"

destination="${PREFIX}/cwpilot"
cwpilot_version="${VERSIONS_DIR}/${VERSION}"
cached_binary="${cwpilot_version}/cwpilot"

mkdir -p "$PREFIX" "$cwpilot_version"

# A previous version rejected an existing destination with "already exists (use
# --force)". The cache is now keyed by (resolved) version, so a cached release can be
# reused and the stable link below can always move to the requested version.
if [ "$FORCE" -ne 1 ] && [ -f "$cached_binary" ]; then
    chmod 0755 "$cached_binary"
else
    command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
    if command -v sha256sum >/dev/null 2>&1; then
        SHA256=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        SHA256="shasum -a 256"
    else
        echo "error: sha256sum or shasum is required" >&2
        exit 1
    fi
    command -v openssl >/dev/null 2>&1 || {
        echo "error: openssl is required to verify release signatures" >&2
        exit 1
    }

    # The release JSON GitHub's API returns is pretty-printed one field per line, so a
    # small state machine tracking the most recently seen "name" is enough to pull out
    # the matching asset's digest -- no JSON parser needed, which matters since this
    # script has to run with nothing but curl, openssl and POSIX awk on whatever box
    # it's piped into.
    extract_digest() {
        json_file="$1"; want="$2"
        awk -v want="$want" '
            /"name":/ {
                line = $0
                sub(/^[^"]*"name": *"/, "", line)
                sub(/".*$/, "", line)
                name = line
            }
            /"digest": *"sha256:/ {
                if (name == want) {
                    line = $0
                    sub(/^[^"]*"digest": *"sha256:/, "", line)
                    sub(/".*$/, "", line)
                    print line
                    exit
                }
            }
        ' "$json_file"
    }

    ensure_tmpdir
    binary="${tmpdir}/${ASSET}"
    signature="${tmpdir}/${ASSET}.sig"
    pubkey_file="${tmpdir}/signing.pub"
    fetch "release binary" "${RELEASE_URL}/${ASSET}" "$binary"
    fetch "release signature" "${RELEASE_URL}/${ASSET}.sig" "$signature"

    # GitHub computes and stores a sha256 "digest" for every uploaded release asset --
    # it's already in the release, so there's no need to also publish (and fetch) a
    # separate *.sha256 sidecar file. The digest is only exposed through the REST API,
    # not the plain releases/download/... URLs used above for the binary and signature.
    # When VERSION was resolved from "latest" above, that request already pulled this
    # same release's metadata -- reuse it instead of asking the API twice.
    if [ -n "$prefetched_metadata" ]; then
        metadata="$prefetched_metadata"
    else
        metadata="${tmpdir}/release.json"
        fetch "release metadata" "$API_URL" "$metadata" -H "Accept: application/vnd.github+json"
    fi

    expected="$(extract_digest "$metadata" "$ASSET")"
    [ -n "$expected" ] || {
        echo "error: no sha256 digest found for asset ${ASSET} in release metadata (${API_URL})" >&2
        exit 1
    }
    actual="$($SHA256 "$binary" | awk '{print $1}')"
    [ "$expected" = "$actual" ] || {
        echo "error: checksum verification failed for ${ASSET} (expected ${expected}, got ${actual})" >&2
        exit 1
    }

    # CWPILOT_SIGNING_PUBKEY lets a different trust root be pointed at -- for testing
    # against a self-signed release, or after a key rotation lands upstream faster than
    # this script does. It names a KEY FILE, never disables the check.
    if [ -n "${CWPILOT_SIGNING_PUBKEY:-}" ]; then
        [ -f "$CWPILOT_SIGNING_PUBKEY" ] || {
            echo "error: CWPILOT_SIGNING_PUBKEY does not exist: ${CWPILOT_SIGNING_PUBKEY}" >&2
            exit 1
        }
        pubkey_file="$CWPILOT_SIGNING_PUBKEY"
    else
        printf '%s\n' "$PUBKEY_PEM" > "$pubkey_file"
    fi

    if ! openssl dgst -sha256 -verify "$pubkey_file" -signature "$signature" "$binary" >/dev/null 2>&1; then
        echo "error: signature verification failed for ${ASSET} -- refusing to install" >&2
        exit 1
    fi

    chmod 0755 "$binary"
    cache_tmp="${cached_binary}.tmp.$$"
    cp "$binary" "$cache_tmp"
    chmod 0755 "$cache_tmp"
    mv -f "$cache_tmp" "$cached_binary"
fi

# Replace the stable link in one rename. Readers see the old version or the new one,
# never the gap that ln -sfn would create. The target is absolute since VERSIONS_DIR
# (~/.local/share/cwpilot-versions) need not share a parent with PREFIX, and every
# older versioned directory stays in place for rollback.
link_tmp="${destination}.link.$$"
ln -s "${cwpilot_version}/cwpilot" "$link_tmp"
mv -f "$link_tmp" "$destination"
echo "installed cwpilot ${VERSION} (${PLATFORM}) to ${destination}"
