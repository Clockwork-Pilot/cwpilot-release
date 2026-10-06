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
#
# The signature is EMBEDDED in each release binary, as a trailer at the very end of the
# file (there is no separate .sig asset):
#
#     <payload> <signature: N bytes> <N: 4 bytes, big-endian> "CWPSIG01"
#
# and covers <payload> only. The installed file is the downloaded file, trailer included
# (ELF/Mach-O loaders ignore trailing bytes), so it can be re-verified later, by the
# plugin, from the binary alone. Writer: sign-embedded.sh in cwpilot / code-plugin.
#
# openssl specifically (not cosign, not anything else) because this script is piped
# through `curl | sh` onto a bare machine with no install step of its own -- openssl
# ships preinstalled on macOS and virtually every desktop Linux distro, so the
# signature check works out of the box instead of adding a dependency this installer
# would then have to install itself.
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
# hookrunner is released from the public plugin repo, not the cwpilot release repo.
HOOKRUNNER_REPOSITORY="${HOOKRUNNER_REPOSITORY:-Clockwork-Pilot/code-plugin}"
HOOKRUNNER_BASE_URL="${HOOKRUNNER_RELEASE_BASE_URL:-https://github.com/${HOOKRUNNER_REPOSITORY}/releases}"
COMPONENT=""

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
Usage: install.sh [cwpilot|hookrunner] [VERSION] [--prefix DIRECTORY] [--force]

With no component named, installs the whole cwpilot world: cwpilot and hookrunner.
Name "cwpilot" or "hookrunner" to install only that one. ("--hookrunner VERSION" is
kept as an alias for "hookrunner VERSION".)

cwpilot comes from the Clockwork-Pilot release assets. hookrunner comes from the
plugin's releases and is stored next to the cwpilot versions as
<versions dir>/hookrunner-v<VERSION>/hookrunner; the newest two such directories are
kept. Both carry an embedded signature, verified against the same key. VERSION is resolved
independently in each repo, so it must exist in both when installing everything.

VERSION defaults to "latest" when omitted (or CWPILOT_VERSION is unset), which
resolves to whatever release GitHub currently marks latest -- re-resolved on every
run, not cached under its own alias.

For cwpilot, VERSION is a bare major.minor (e.g. 0.1, or v0.1): it resolves to that
family's newest patch release, without ever crossing into a different major.minor.
cwpilot never takes a patch: "cwpilot 0.1.2" is an error. When installing everything,
a full X.Y.Z is accepted -- cwpilot uses its X.Y and hookrunner keeps the exact X.Y.Z.

Re-running updates the stable link; --force re-downloads the requested version.
Only the version just linked and whichever one was linked immediately before it
are kept on disk -- one fallback to roll back to, not unbounded history.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            [ "$#" -ge 2 ] || { echo "error: --prefix needs a value" >&2; exit 2; }
            PREFIX="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --hookrunner)
            # Kept for the plugin: same as `hookrunner VERSION`.
            [ "$#" -ge 2 ] || { echo "error: --hookrunner needs a version" >&2; exit 2; }
            COMPONENT=hookrunner; VERSION="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --*) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
        cwpilot|hookrunner) COMPONENT="$1"; shift ;;
        *) VERSION="$1"; shift ;;
    esac
done
# One VERSION spec drives whichever components are installed.
HOOKRUNNER_VERSION="$VERSION"

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

TRAILER_MAGIC="CWPSIG01"
TRAILER_FIXED_BYTES=12   # 4-byte length + 8-byte magic
TRAILER_MAX_SIGNATURE_BYTES=1024

# Sets SIGNING_KEY_FILE to the public key signatures are checked against: the embedded
# one, or the key file CWPILOT_SIGNING_PUBKEY names -- for testing against a self-signed
# release, or after a key rotation lands upstream faster than this script does; it names
# a KEY FILE, never disables the check. The key is NOT stored anywhere afterwards: the
# plugin carries its own copy, and nothing read back from the versions dir is trusted.
signature_key_file() {
    command -v openssl >/dev/null 2>&1 || {
        echo "error: openssl is required to verify release signatures" >&2
        exit 1
    }
    ensure_tmpdir
    if [ -n "${CWPILOT_SIGNING_PUBKEY:-}" ]; then
        [ -f "$CWPILOT_SIGNING_PUBKEY" ] || {
            echo "error: CWPILOT_SIGNING_PUBKEY does not exist: ${CWPILOT_SIGNING_PUBKEY}" >&2
            exit 1
        }
        SIGNING_KEY_FILE="$CWPILOT_SIGNING_PUBKEY"
    else
        SIGNING_KEY_FILE="${tmpdir}/signing.pub"
        printf '%s\n' "$PUBKEY_PEM" > "$SIGNING_KEY_FILE"
    fi
}

# Status 0 when $1 carries a well-formed embedded signature that verifies, 1 otherwise
# (no trailer, a malformed one, or a bad signature). Never exits on a bad file, so a
# caller can treat "not signed" as "not cached"; a missing trailer is a failure, never a
# pass. Needs only tail, head, od, wc, cmp and openssl.
signature_ok() {
    so_file="$1"
    signature_key_file
    so_size="$(wc -c < "$so_file" | tr -d ' ')"
    [ "$so_size" -gt "$TRAILER_FIXED_BYTES" ] || return 1
    printf '%s' "$TRAILER_MAGIC" > "${tmpdir}/trailer.magic"
    tail -c 8 "$so_file" | cmp -s - "${tmpdir}/trailer.magic" || return 1
    # The length field: 4 bytes, big-endian, read as decimal bytes.
    set -- $(tail -c "$TRAILER_FIXED_BYTES" "$so_file" | head -c 4 | od -An -tu1)
    [ "$#" -eq 4 ] || return 1
    so_siglen=$(( $1 * 16777216 + $2 * 65536 + $3 * 256 + $4 ))
    [ "$so_siglen" -ge 1 ] && [ "$so_siglen" -le "$TRAILER_MAX_SIGNATURE_BYTES" ] || return 1
    so_trailer=$(( so_siglen + TRAILER_FIXED_BYTES ))
    [ "$so_trailer" -lt "$so_size" ] || return 1
    tail -c "$so_trailer" "$so_file" | head -c "$so_siglen" > "${tmpdir}/embedded.sig"
    head -c "$(( so_size - so_trailer ))" "$so_file" |
        openssl dgst -sha256 -verify "$SIGNING_KEY_FILE" -signature "${tmpdir}/embedded.sig" >/dev/null 2>&1
}

# Verify the signature embedded in $1. Exits the whole script on any failure: nothing
# unverified is ever installed.
verify_signature() {
    if ! signature_ok "$1"; then
        echo "error: signature verification failed for $(basename "$1") -- refusing to install" >&2
        exit 1
    fi
}

# ── hookrunner: a different binary from a different repo ────────────────────────
# VERSION is resolved against the hookrunner repo the same way cwpilot's is (empty or
# "latest", a bare major.minor, or an exact tag); the plugin passes an exact one. The
# binary is downloaded and its embedded signature verified BEFORE anything lands in the
# versions directory.
resolve_hookrunner_tag() {
    spec="$1"
    case "$spec" in
        ""|latest)
            ensure_tmpdir
            fetch "latest hookrunner release metadata" \
                "https://api.github.com/repos/${HOOKRUNNER_REPOSITORY}/releases/latest" \
                "${tmpdir}/hr-latest.json" -H "Accept: application/vnd.github+json"
            spec="$(awk '/"tag_name":/ { l = $0; sub(/^[^"]*"tag_name": *"/, "", l); sub(/".*$/, "", l); print l; exit }' \
                "${tmpdir}/hr-latest.json")"
            [ -n "$spec" ] || { echo "error: no tag_name found in latest hookrunner release metadata" >&2; exit 1; }
            ;;
        *)
            bare="${spec#v}"
            case "$bare" in
                *.*.*) ;;
                *.*)
                    ensure_tmpdir
                    fetch "hookrunner release list" \
                        "https://api.github.com/repos/${HOOKRUNNER_REPOSITORY}/releases" \
                        "${tmpdir}/hr-list.json" -H "Accept: application/vnd.github+json"
                    spec="$(newest_patch_in_family "${tmpdir}/hr-list.json" "$bare")"
                    [ -n "$spec" ] || { echo "error: no release found for ${bare}.x in ${HOOKRUNNER_REPOSITORY}" >&2; exit 1; }
                    ;;
            esac
            ;;
    esac
    case "$spec" in
        v*) ;;
        *) spec="v${spec}" ;;
    esac
    case "$spec" in
        v|*/*|*..*) echo "error: invalid hookrunner version: ${spec}" >&2; exit 2 ;;
    esac
    printf '%s\n' "$spec"
}

install_hookrunner() {
    command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
    # Only these platforms have a published hookrunner build; anywhere else the plugin
    # simply keeps running its hooks from Python source, so say that instead of 404ing.
    # Skipped (not fatal) when installing everything, an error when asked for by name.
    case "$PLATFORM" in
        linux-x86_64|darwin-arm64) ;;
        *)
            if [ "$COMPONENT" = hookrunner ]; then
                echo "error: no hookrunner build is published for ${PLATFORM}; the plugin runs its hooks from Python source there" >&2
                exit 1
            fi
            echo "skipped hookrunner: no build is published for ${PLATFORM}; the plugin runs its hooks from Python source there"
            return 0 ;;
    esac
    HOOKRUNNER_VERSION="$(resolve_hookrunner_tag "$HOOKRUNNER_VERSION")"
    hr_asset="hookrunner-${PLATFORM}"
    hr_dir="${VERSIONS_DIR}/hookrunner-${HOOKRUNNER_VERSION}"
    # Installed means present AND carrying a valid embedded signature: a hookrunner from
    # before signatures were embedded is fetched again, once.
    if [ "$FORCE" -ne 1 ] && [ -f "${hr_dir}/hookrunner" ] && signature_ok "${hr_dir}/hookrunner"; then
        echo "hookrunner ${HOOKRUNNER_VERSION} (${PLATFORM}) already installed at ${hr_dir}/hookrunner"
        return 0
    fi
    ensure_tmpdir
    hr_url="${HOOKRUNNER_BASE_URL}/download/${HOOKRUNNER_VERSION}"
    fetch "hookrunner binary" "${hr_url}/${hr_asset}" "${tmpdir}/${hr_asset}"
    verify_signature "${tmpdir}/${hr_asset}"

    mkdir -p "$hr_dir"
    cache_tmp="${hr_dir}/hookrunner.tmp.$$"
    cp "${tmpdir}/${hr_asset}" "$cache_tmp"
    chmod 0755 "$cache_tmp"
    mv -f "$cache_tmp" "${hr_dir}/hookrunner"
    echo "installed hookrunner ${HOOKRUNNER_VERSION} (${PLATFORM}) to ${hr_dir}/hookrunner"

    # Keep the two most recently installed hookrunner versions: current + one to roll
    # back to. Only hookrunner-v* directories -- never a cwpilot v* one.
    ls -1dt "${VERSIONS_DIR}"/hookrunner-v* 2>/dev/null | tail -n +3 |
        while IFS= read -r stale; do
            [ -d "$stale" ] && rm -rf "$stale"
        done
    return 0
}

# Given a full "GET .../releases" list response (pretty-printed JSON, one field per
# line -- same shape the single-release lookups elsewhere in this script already
# assume) and a bare "major.minor" family, prints that family's highest-patch tag, or
# nothing if none match. Field-by-field comparison rather than a regex built from
# `family`, so a literal "." in it is never accidentally treated as "any character".
newest_patch_in_family() {
    json_file="$1"; family="$2"
    awk -v family="$family" '
        BEGIN { split(family, f, "."); fmajor = f[1]; fminor = f[2] }
        /"tag_name":/ {
            line = $0
            sub(/^[^"]*"tag_name": *"/, "", line)
            sub(/".*$/, "", line)
            tag = line
            bare = tag
            sub(/^v/, "", bare)
            nf = split(bare, parts, ".")
            if (nf == 3 && parts[1] == fmajor && parts[2] == fminor && parts[3] ~ /^[0-9]+$/) {
                patch = parts[3] + 0
                if (best_tag == "" || patch > best_patch) {
                    best_patch = patch
                    best_tag = tag
                }
            }
        }
        END { if (best_tag != "") print best_tag }
    ' "$json_file"
}

install_cwpilot() {
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
    else
        # A bare major.minor (exactly one dot once any "v" is stripped, e.g. "0.1" or
        # "v0.1") resolves to that family's newest patch via the full release list --
        # "major.minor" can't exist as a literal tag. A full major.minor.patch (two dots)
        # falls straight through, normalized below exactly as before; this is the only
        # new shape.
        bare="${VERSION#v}"
        case "$bare" in
            *.*.*) ;;
            *.*)
                command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
                ensure_tmpdir
                family_list="${tmpdir}/releases.json"
                # The default page (30 releases) is assumed to cover this family -- fine
                # for a project this young; revisit with ?per_page=/pagination once release
                # history outgrows one page.
                fetch "release list" "https://api.github.com/repos/${REPOSITORY}/releases" \
                    "$family_list" -H "Accept: application/vnd.github+json"
                resolved="$(newest_patch_in_family "$family_list" "$bare")"
                [ -n "$resolved" ] || {
                    echo "error: no release found for ${bare}.x in ${REPOSITORY}" >&2
                    exit 1
                }
                VERSION="$resolved"
                ;;
        esac
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
    # A cached binary is reused only while it still carries a valid embedded signature:
    # one from before signatures were embedded (or one that no longer verifies) is
    # downloaded and verified again rather than trusted.
    if [ "$FORCE" -ne 1 ] && [ -f "$cached_binary" ] && signature_ok "$cached_binary"; then
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
        fetch "release binary" "${RELEASE_URL}/${ASSET}" "$binary"

        # GitHub computes and stores a sha256 "digest" for every uploaded release asset --
        # it's already in the release, so there's no need to also publish (and fetch) a
        # separate *.sha256 sidecar file. The digest is only exposed through the REST API,
        # not the plain releases/download/... URL used above for the binary.
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

        verify_signature "$binary"

        chmod 0755 "$binary"
        # The embedded signature travels with the file, so anything can re-check it later.
        cache_tmp="${cached_binary}.tmp.$$"
        cp "$binary" "$cache_tmp"
        chmod 0755 "$cache_tmp"
        mv -f "$cache_tmp" "$cached_binary"
    fi

    # Capture what the stable link currently points at, BEFORE it moves, so it can be kept
    # as the rollback fallback below. Only trusted when it actually points inside
    # VERSIONS_DIR -- anything else (missing, a plain file, a foreign path) means there's
    # no known-previous version to protect from pruning.
    previous_version=""
    if [ -L "$destination" ]; then
        prev_target="$(readlink "$destination")"
        case "$prev_target" in
            "${VERSIONS_DIR}"/*/cwpilot)
                previous_version="${prev_target#"${VERSIONS_DIR}"/}"
                previous_version="${previous_version%/cwpilot}"
                ;;
        esac
    fi

    # Replace the stable link in one rename. Readers see the old version or the new one,
    # never the gap that ln -sfn would create. The target is absolute since VERSIONS_DIR
    # (~/.local/share/cwpilot-versions) need not share a parent with PREFIX.
    link_tmp="${destination}.link.$$"
    ln -s "${cwpilot_version}/cwpilot" "$link_tmp"
    mv -f "$link_tmp" "$destination"
    echo "installed cwpilot ${VERSION} (${PLATFORM}) to ${destination}"

    # Retention: keep only the version just linked and whichever one was linked
    # immediately before it -- current + previous, exactly one fallback to roll back to
    # if the new install turns out to be bad, with no unbounded growth. Nothing to prune
    # when they're the same version (e.g. a same-version --force re-run) -- there both is
    # and only ever was one copy on disk.
    if [ -n "${previous_version}" ] && [ "${previous_version}" != "${VERSION}" ] && [ -d "${VERSIONS_DIR}" ]; then
        # Only cwpilot's own v* directories: hookrunner-v* ones (and anything else that
        # shares this directory) are not this retention rule's to delete.
        for dir in "${VERSIONS_DIR}"/v*; do
            [ -d "${dir}" ] || continue
            case "$(basename "${dir}")" in
                "${VERSION}" | "${previous_version}") ;;
                *) rm -rf "${dir}" ;;
            esac
        done
    fi
}


# Warn (never fail) when the install prefix isn't on $PATH, so the user knows why a
# freshly installed cwpilot/hookrunner "isn't found".
check_path() {
    case ":${PATH:-}:" in
        *":${PREFIX%/}:"* | *":${PREFIX%/}/:"*) return 0 ;;
    esac
    echo "warning: ${PREFIX} is not in your \$PATH, so cwpilot and hookrunner won't be found by name." >&2
    echo "         add it for this shell and future ones with:" >&2
    echo "           echo 'export PATH=\"${PREFIX}:\$PATH\"' >> ~/.bashrc && export PATH=\"${PREFIX}:\$PATH\"" >&2
}

# ── Dispatch: no component named installs everything ─────────────────────────────
case "$COMPONENT" in
    cwpilot)
        # cwpilot only ever tracks a major.minor family (newest patch) or "latest";
        # an exact patch is the hookrunner's scheme, not its.
        if printf '%s' "$VERSION" | awk '{ s = $0 } END { exit !(s ~ /^v?[0-9]+\.[0-9]+\.[0-9]+$/) }'; then
            fam="${VERSION#v}"; fam="${fam%.*}"
            echo "error: invalid version: ${VERSION} -- cwpilot takes major.minor (e.g. ${fam}), not a patch" >&2
            exit 2
        fi
        install_cwpilot ;;
    hookrunner) install_hookrunner ;;
    *)
        # hookrunner is per-patch (it keeps the exact VERSION), while cwpilot only
        # tracks the plugin's major.minor and always takes that family's newest patch.
        case "${VERSION#v}" in
            *.*.*) VERSION="${VERSION#v}"; VERSION="${VERSION%.*}" ;;
        esac
        install_cwpilot
        install_hookrunner ;;
esac

check_path
