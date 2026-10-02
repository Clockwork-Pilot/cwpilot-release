#!/usr/bin/env python3
"""Behavioral tests for install.sh, run against the real shell script as a subprocess.

No external Python dependencies (stdlib unittest only), matching install.sh's own
"nothing but curl, openssl and POSIX awk" constraint. Network access is stubbed out
by putting a fake `curl` first on PATH; every other tool (sh, awk, openssl,
sha256sum, ...) is the real system binary, symlinked into an isolated tool
directory so tests don't depend on the ambient PATH.

Run with:  python3 -m unittest discover -s tests -v
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"

# External tools install.sh shells out to, other than curl (which each test stubs
# itself). Symlinked into an isolated bin dir so PATH never leaks the ambient
# environment's curl (or anything else) into a test.
REQUIRED_TOOLS = [
    "sh", "uname", "tr", "mkdir", "chmod", "sha256sum", "shasum", "openssl",
    "awk", "mktemp", "cp", "mv", "rm", "ln", "cat", "printf", "dirname",
    "readlink", "basename", "ls", "tail",
]

FAKE_CURL_SCRIPT = """
import json
import os
import shutil
import sys


def main():
    argv = sys.argv[1:]
    out = None
    url = None
    i = 0
    while i < len(argv):
        if argv[i] == "-o" and i + 1 < len(argv):
            out = argv[i + 1]
            i += 2
            continue
        if argv[i].startswith("http"):
            url = argv[i]
        i += 1

    log_path = os.environ.get("FAKE_CURL_LOG")
    if log_path:
        with open(log_path, "a") as f:
            f.write((url or "") + "\\n")

    with open(os.environ["FAKE_CURL_RULES"]) as f:
        rules = json.load(f)

    for rule in rules:
        if rule["match"] in (url or ""):
            action = rule["action"]
            if action == "content":
                with open(out, "w") as f:
                    f.write(rule["body"])
                return 0
            if action == "copy":
                shutil.copyfile(rule["src"], out)
                return 0
            if action == "fail":
                sys.stderr.write(rule.get("message", "simulated curl failure") + "\\n")
                return rule.get("code", 22)

    sys.stderr.write("fake curl: no rule matched url: %s\\n" % url)
    return 1


if __name__ == "__main__":
    sys.exit(main())
"""


def detect_platform() -> str:
    """Mirrors install.sh's own PLATFORM derivation, so tests target the asset
    name the script under test will actually ask for."""
    system = subprocess.run(["uname", "-s"], capture_output=True, text=True, check=True).stdout.strip().lower()
    machine = subprocess.run(["uname", "-m"], capture_output=True, text=True, check=True).stdout.strip()
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}[machine]
    return f"{system}-{arch}"


PLATFORM = detect_platform()
ASSET = f"cwpilot-{PLATFORM}"


def release_json(tag_name: str, asset_name: str, digest_hex: str) -> str:
    return json.dumps(
        {"tag_name": tag_name, "assets": [{"name": asset_name, "digest": f"sha256:{digest_hex}"}]},
        indent=2,
    )


def release_list_json(tags: list) -> str:
    """A GET .../releases (list) response body for the given tags, same
    pretty-printed shape as a single release object."""
    return json.dumps(
        [{"tag_name": tag, "assets": [{"name": f"cwpilot-{PLATFORM}", "digest": "sha256:" + "0" * 64}]} for tag in tags],
        indent=2,
    )


class InstallShTestCase(unittest.TestCase):
    """Each test gets its own isolated HOME, tool PATH, and fake-curl rule set."""

    def setUp(self):
        self.work = Path(self._mkdtemp())
        self.home = self.work / "home"
        self.home.mkdir()
        self.toolbin = self.work / "toolbin"
        self.toolbin.mkdir()
        for name in REQUIRED_TOOLS:
            found = shutil.which(name)
            if found:
                os.symlink(found, self.toolbin / name)

        self.rules_file = self.work / "curl_rules.json"
        self.rules_file.write_text("[]")
        self.log_file = self.work / "curl.log"

        self.env = {
            "HOME": str(self.home),
            "PATH": str(self.toolbin),
            "FAKE_CURL_RULES": str(self.rules_file),
            "FAKE_CURL_LOG": str(self.log_file),
        }

    def _mkdtemp(self) -> str:
        import tempfile
        d = tempfile.mkdtemp(prefix="cwpilot-install-test-")
        self.addCleanup(shutil.rmtree, d, True)
        return d

    # -- helpers ----------------------------------------------------------------

    def install_fake_curl(self):
        script_path = self.toolbin / "curl"
        script_path.write_text(f"#!{sys.executable}\n{FAKE_CURL_SCRIPT}")
        script_path.chmod(0o755)

    def set_rules(self, rules):
        self.rules_file.write_text(json.dumps(rules))

    def curl_calls(self):
        if not self.log_file.exists():
            return []
        return [line for line in self.log_file.read_text().splitlines() if line]

    def seed_cached_version(self, version: str, content: bytes = b"#!/bin/sh\necho cached\n",
                            with_sig: bool = True):
        version_dir = self.home / ".local" / "share" / "cwpilot-versions" / version
        version_dir.mkdir(parents=True)
        binary = version_dir / "cwpilot"
        binary.write_bytes(content)
        binary.chmod(0o755)
        if with_sig:
            # Any content: a cache hit with a sig present never re-verifies or goes online.
            (version_dir / "cwpilot.sig").write_bytes(b"stored-sig")
        return binary

    def run_install(self, *args, extra_env=None):
        env = dict(self.env)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["sh", str(INSTALL_SH), *args],
            env=env,
            capture_output=True,
            text=True,
        )

    def stable_link(self) -> Path:
        return self.home / ".local" / "bin" / "cwpilot"

    def versions_dir(self) -> Path:
        return self.home / ".local" / "share" / "cwpilot-versions"

    def version_dirs(self) -> list:
        """cwpilot's own v* version directories (ignores signing.pub and hookrunner-v*)."""
        return sorted(p.name for p in self.versions_dir().iterdir() if p.name.startswith("v"))

    def make_signed_release(self, tag: str, content: bytes = b"#!/bin/sh\necho downloaded\n"):
        """Builds a real RSA keypair + signature for `content`, and matching curl
        rules, so cold-download tests exercise real checksum and signature
        verification instead of stubbing it away. `tag` must already be the
        canonical, v-prefixed tag (e.g. "v2.0.0") -- install.sh's download and
        tags-API URLs are keyed on the literal tag, v and all."""
        assert tag.startswith("v"), "GitHub tags in this repo are v-prefixed"

        priv = self.work / f"{tag}-priv.pem"
        pub = self.work / f"{tag}-pub.pem"
        binary = self.work / f"{tag}-{ASSET}"
        sig = self.work / f"{tag}-{ASSET}.sig"

        binary.write_bytes(content)
        subprocess.run(["openssl", "genrsa", "-out", str(priv), "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", str(priv), "-pubout", "-out", str(pub)], check=True, capture_output=True)
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(priv), "-out", str(sig), str(binary)],
            check=True, capture_output=True,
        )
        digest = hashlib.sha256(content).hexdigest()
        return {
            "tag": tag,
            "pub": pub,
            "binary": binary,
            "sig": sig,
            "digest": digest,
            "metadata_rule": {
                "match": "releases/latest",
                "action": "content",
                "body": release_json(tag, ASSET, digest),
            },
            "tags_rule": {
                "match": f"releases/tags/{tag}",
                "action": "content",
                "body": release_json(tag, ASSET, digest),
            },
            # Order matters: the .sig rule must be checked before the plain binary
            # rule, since its URL is a superset match of the binary URL's suffix.
            "binary_rule": {"match": f"download/{tag}/{ASSET}.sig", "action": "copy", "src": str(sig)},
            "download_rule": {"match": f"download/{tag}/{ASSET}", "action": "copy", "src": str(binary)},
        }

    # -- tests --------------------------------------------------------------

    def test_pinned_cache_hit_never_touches_network(self):
        self.install_fake_curl()
        self.set_rules([{"match": "", "action": "fail", "message": "network should not be used"}])
        self.seed_cached_version("v1.2.3", content=b"#!/bin/sh\necho already-cached\n")

        result = self.run_install("v1.2.3")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.curl_calls(), [], "explicit pinned version with a cache hit must stay offline")
        self.assertEqual(os.readlink(self.stable_link()), str(self.versions_dir() / "v1.2.3" / "cwpilot"))

    def test_bare_version_normalizes_to_v_prefixed_tag_and_reuses_cache(self):
        # GitHub tags in this repo are v-prefixed (v1.2.3); a bare "1.2.3" typed on
        # the command line must normalize to that tag rather than being treated as
        # a different, unrelated version.
        self.install_fake_curl()
        self.set_rules([{"match": "", "action": "fail", "message": "network should not be used"}])
        self.seed_cached_version("v1.2.3", content=b"#!/bin/sh\necho already-cached\n")

        result = self.run_install("1.2.3")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("installed cwpilot v1.2.3", result.stdout)
        self.assertEqual(self.curl_calls(), [], "normalized version with a cache hit must stay offline")
        self.assertEqual(
            self.version_dirs(), ["v1.2.3"],
            "a bare version must resolve to the same cache directory as its v-prefixed tag",
        )
        self.assertEqual(os.readlink(self.stable_link()), str(self.versions_dir() / "v1.2.3" / "cwpilot"))

    def test_latest_resolves_to_already_cached_pinned_version_no_duplicate(self):
        # The bug this suite exists for: installing "latest" when it happens to
        # resolve to an already-cached explicit tag must reuse that directory,
        # not create a second "latest" copy of the same release.
        self.install_fake_curl()
        self.set_rules([
            {"match": "releases/latest", "action": "content", "body": release_json("v1.1.1", ASSET, "unused")},
        ])
        self.seed_cached_version("v1.1.1", content=b"#!/bin/sh\necho pinned-1.1.1\n")

        result = self.run_install()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("installed cwpilot v1.1.1", result.stdout)
        self.assertEqual(
            self.version_dirs(), ["v1.1.1"],
            "resolving latest must not create a separate 'latest' directory",
        )
        self.assertEqual(os.readlink(self.stable_link()), str(self.versions_dir() / "v1.1.1" / "cwpilot"))
        # Only the metadata lookup should happen -- no binary/signature re-download
        # for a release that's already cached under its resolved tag.
        self.assertEqual(len(self.curl_calls()), 1)
        self.assertIn("releases/latest", self.curl_calls()[0])

    def test_latest_cold_download_verifies_and_caches_under_resolved_tag(self):
        self.install_fake_curl()
        release = self.make_signed_release("v2.0.0", content=b"#!/bin/sh\necho fresh-2.0.0\n")
        self.set_rules([release["metadata_rule"], release["binary_rule"], release["download_rule"]])

        result = self.run_install(extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("installed cwpilot v2.0.0", result.stdout)
        installed = self.versions_dir() / "v2.0.0" / "cwpilot"
        self.assertTrue(installed.exists())
        self.assertEqual(installed.read_bytes(), release["binary"].read_bytes())
        self.assertTrue(os.access(installed, os.X_OK))
        self.assertEqual(os.readlink(self.stable_link()), str(installed))

    def test_second_latest_run_same_tag_reuses_cache_without_redownload(self):
        self.install_fake_curl()
        release = self.make_signed_release("v2.0.0", content=b"#!/bin/sh\necho fresh-2.0.0\n")
        self.set_rules([release["metadata_rule"], release["binary_rule"], release["download_rule"]])
        first = self.run_install(extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})
        self.assertEqual(first.returncode, 0, first.stderr)

        # Second run: only the metadata lookup is allowed to succeed: prove the
        # binary/signature are not re-fetched once the resolved tag is cached.
        self.set_rules([
            release["metadata_rule"],
            {"match": f"download/v2.0.0/{ASSET}", "action": "fail", "message": "must not be called"},
        ])
        second = self.run_install(extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})

        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.version_dirs(), ["v2.0.0"])

    def test_checksum_mismatch_is_rejected_and_leaves_no_partial_cache(self):
        self.install_fake_curl()
        release = self.make_signed_release("v3.0.0")
        bad_metadata = {
            "match": "releases/latest",
            "action": "content",
            "body": release_json("v3.0.0", ASSET, "0" * 64),  # wrong digest
        }
        self.set_rules([bad_metadata, release["binary_rule"], release["download_rule"]])

        result = self.run_install(extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum verification failed", result.stderr)
        # mkdir -p creates the (empty) version directory upfront; what matters is
        # that a failed verification never places a binary inside it.
        self.assertFalse((self.versions_dir() / "v3.0.0" / "cwpilot").exists())
        self.assertFalse(self.stable_link().exists())

    def test_signature_mismatch_is_rejected_and_leaves_no_partial_cache(self):
        self.install_fake_curl()
        release = self.make_signed_release("v4.0.0")
        # Verify against an unrelated key -- the digest still matches (checksum
        # only catches transit corruption), so this isolates the signature check.
        other_pub = self.work / "other-pub.pem"
        other_priv = self.work / "other-priv.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(other_priv), "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", str(other_priv), "-pubout", "-out", str(other_pub)], check=True, capture_output=True)
        self.set_rules([release["metadata_rule"], release["binary_rule"], release["download_rule"]])

        result = self.run_install(extra_env={"CWPILOT_SIGNING_PUBKEY": str(other_pub)})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature verification failed", result.stderr)
        self.assertFalse((self.versions_dir() / "v4.0.0" / "cwpilot").exists())

    def test_force_redownloads_and_overwrites_existing_cache(self):
        self.install_fake_curl()
        self.seed_cached_version("v1.5.0", content=b"#!/bin/sh\necho stale\n")
        release = self.make_signed_release("v1.5.0", content=b"#!/bin/sh\necho refreshed\n")
        self.set_rules([release["tags_rule"], release["binary_rule"], release["download_rule"]])

        # Bare "1.5.0" on top of --force also proves normalization still applies
        # when the cache-hit shortcut is bypassed.
        result = self.run_install("1.5.0", "--force", extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})

        self.assertEqual(result.returncode, 0, result.stderr)
        installed = self.versions_dir() / "v1.5.0" / "cwpilot"
        self.assertEqual(installed.read_bytes(), b"#!/bin/sh\necho refreshed\n")
        self.assertGreaterEqual(len(self.curl_calls()), 2, "--force must hit the network even on a cache hit")

    def test_rejects_path_traversal_version(self):
        self.install_fake_curl()
        self.set_rules([{"match": "", "action": "fail", "message": "network should not be used"}])

        for traversal in ("../../etc", "v/../../etc"):
            with self.subTest(version=traversal):
                result = self.run_install(traversal)
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid version", result.stderr)

        self.assertEqual(self.curl_calls(), [])

    def test_bare_major_minor_resolves_to_newest_patch_in_that_family(self):
        self.install_fake_curl()
        self.set_rules([
            {"match": "/releases", "action": "content",
             "body": release_list_json(["v0.2.0", "v0.1.0", "v0.1.3", "v0.1.2"])},
        ])
        self.seed_cached_version("v0.1.3", content=b"#!/bin/sh\necho family-newest\n")

        result = self.run_install("0.1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("installed cwpilot v0.1.3", result.stdout)
        self.assertEqual(os.readlink(self.stable_link()), str(self.versions_dir() / "v0.1.3" / "cwpilot"))

    def test_bare_major_minor_never_crosses_into_a_different_family(self):
        # The overall newest release (v0.2.5) must never be picked just because a
        # bare major.minor was given -- only that family's own newest patch.
        self.install_fake_curl()
        self.set_rules([
            {"match": "/releases", "action": "content",
             "body": release_list_json(["v0.2.5", "v0.1.1"])},
        ])
        self.seed_cached_version("v0.1.1")

        result = self.run_install("v0.1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("installed cwpilot v0.1.1", result.stdout)

    def test_bare_major_minor_with_no_matching_release_errors(self):
        self.install_fake_curl()
        self.set_rules([
            {"match": "/releases", "action": "content", "body": release_list_json(["v0.2.0"])},
        ])

        result = self.run_install("0.1")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no release found for 0.1.x", result.stderr)

    def test_full_version_argument_is_unaffected_by_family_resolution(self):
        # A full major.minor.patch must never go through the release-list lookup at
        # all -- proven here by a rules list that only a /releases (list) hit would
        # satisfy, which must never be requested.
        self.install_fake_curl()
        self.set_rules([{"match": "", "action": "fail", "message": "network should not be used"}])
        self.seed_cached_version("v0.1.2")

        result = self.run_install("0.1.2")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.curl_calls(), [])

    def test_prunes_to_current_and_previous_only(self):
        self.install_fake_curl()
        # From before "current + previous" tracking was ever established -- must be
        # swept away the first time a real previous/current pair exists.
        self.seed_cached_version("v0.5.0", content=b"#!/bin/sh\necho orphan\n")

        release_a = self.make_signed_release("v1.0.0", content=b"#!/bin/sh\necho a\n")
        self.set_rules([release_a["tags_rule"], release_a["binary_rule"], release_a["download_rule"]])
        first = self.run_install("v1.0.0", extra_env={"CWPILOT_SIGNING_PUBKEY": str(release_a["pub"])})
        self.assertEqual(first.returncode, 0, first.stderr)
        # Nothing to prune yet -- no stable link existed before this run, so there
        # was no established "previous" to prune around.
        self.assertEqual(
            self.version_dirs(), ["v0.5.0", "v1.0.0"],
        )

        release_b = self.make_signed_release("v2.0.0", content=b"#!/bin/sh\necho b\n")
        self.set_rules([release_b["tags_rule"], release_b["binary_rule"], release_b["download_rule"]])
        second = self.run_install("v2.0.0", extra_env={"CWPILOT_SIGNING_PUBKEY": str(release_b["pub"])})
        self.assertEqual(second.returncode, 0, second.stderr)

        self.assertEqual(
            self.version_dirs(), ["v1.0.0", "v2.0.0"],
            "only the version just installed and the immediately-previous one should remain",
        )
        self.assertEqual(os.readlink(self.stable_link()), str(self.versions_dir() / "v2.0.0" / "cwpilot"))

    def test_force_reinstall_of_same_version_prunes_nothing_extra(self):
        self.install_fake_curl()
        release = self.make_signed_release("v1.5.0", content=b"#!/bin/sh\necho first\n")
        self.set_rules([release["tags_rule"], release["binary_rule"], release["download_rule"]])
        first = self.run_install("v1.5.0", extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})
        self.assertEqual(first.returncode, 0, first.stderr)

        refreshed = self.make_signed_release("v1.5.0", content=b"#!/bin/sh\necho refreshed\n")
        self.set_rules([refreshed["tags_rule"], refreshed["binary_rule"], refreshed["download_rule"]])
        second = self.run_install(
            "v1.5.0", "--force", extra_env={"CWPILOT_SIGNING_PUBKEY": str(refreshed["pub"])},
        )

        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.version_dirs(), ["v1.5.0"])

    def test_latest_requires_curl(self):
        # No fake curl installed at all -- PATH has every other tool but curl.
        result = self.run_install()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("curl is required", result.stderr)

    # -- hookrunner mode -------------------------------------------------------

    def make_signed_hookrunner(self, tag: str, content: bytes = b"#!/bin/sh\necho hookrunner\n"):
        asset = f"hookrunner-{PLATFORM}"
        priv = self.work / f"hr-{tag}-priv.pem"
        pub = self.work / f"hr-{tag}-pub.pem"
        binary = self.work / f"hr-{tag}-{asset}"
        sig = self.work / f"hr-{tag}-{asset}.sig"
        binary.write_bytes(content)
        subprocess.run(["openssl", "genrsa", "-out", str(priv), "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", str(priv), "-pubout", "-out", str(pub)], check=True, capture_output=True)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(priv), "-out", str(sig), str(binary)],
                       check=True, capture_output=True)
        return {
            "pub": pub, "binary": binary, "sig": sig,
            # .sig rule first: its URL also matches the plain-binary rule's substring.
            "rules": [
                {"match": f"download/{tag}/{asset}.sig", "action": "copy", "src": str(sig)},
                {"match": f"download/{tag}/{asset}", "action": "copy", "src": str(binary)},
            ],
        }

    def hookrunner_dir(self, tag: str) -> Path:
        return self.versions_dir() / f"hookrunner-{tag}"

    def test_hookrunner_installs_verified_binary_and_sig_without_the_api(self):
        self.install_fake_curl()
        hr = self.make_signed_hookrunner("v1.2.0")
        self.set_rules(hr["rules"])

        result = self.run_install("--hookrunner", "1.2.0", extra_env={"CWPILOT_SIGNING_PUBKEY": str(hr["pub"])})

        self.assertEqual(result.returncode, 0, result.stderr)
        d = self.hookrunner_dir("v1.2.0")
        self.assertEqual((d / "hookrunner").read_bytes(), hr["binary"].read_bytes())
        self.assertTrue(os.access(d / "hookrunner", os.X_OK))
        self.assertEqual((d / "hookrunner.sig").read_bytes(), hr["sig"].read_bytes())
        self.assertFalse(any("api.github.com" in c for c in self.curl_calls()))
        self.assertFalse(self.stable_link().exists(), "hookrunner mode must not touch the cwpilot link")

    def test_hookrunner_bad_signature_installs_nothing(self):
        self.install_fake_curl()
        hr = self.make_signed_hookrunner("v1.2.0")
        other = self.make_signed_hookrunner("v9.9.9")  # a different key
        self.set_rules(hr["rules"])

        result = self.run_install("--hookrunner", "v1.2.0", extra_env={"CWPILOT_SIGNING_PUBKEY": str(other["pub"])})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature verification failed", result.stderr)
        self.assertFalse(self.hookrunner_dir("v1.2.0").exists())

    def test_hookrunner_already_installed_stays_offline(self):
        self.install_fake_curl()
        self.set_rules([{"match": "", "action": "fail", "message": "network should not be used"}])
        d = self.hookrunner_dir("v1.2.0")
        d.mkdir(parents=True)
        (d / "hookrunner").write_bytes(b"x")
        (d / "hookrunner.sig").write_bytes(b"x")

        result = self.run_install("--hookrunner", "v1.2.0")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.curl_calls(), [])

    def test_hookrunner_on_an_unbuilt_platform_says_so_without_downloading(self):
        self.install_fake_curl()
        self.set_rules([{"match": "", "action": "fail", "message": "network should not be used"}])
        fake_uname = self.toolbin / "uname"
        fake_uname.unlink()
        fake_uname.write_text('#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo aarch64 ;; esac\n')
        fake_uname.chmod(0o755)

        result = self.run_install("--hookrunner", "1.0.0")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no hookrunner build is published for linux-arm64", result.stderr)
        self.assertEqual(self.curl_calls(), [])

    def test_hookrunner_missing_release_fails_cleanly(self):
        self.install_fake_curl()
        self.set_rules([{"match": "download/", "action": "fail", "message": "404"}])

        result = self.run_install("--hookrunner", "v1.2.0")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed to download hookrunner binary", result.stderr)
        self.assertFalse(self.hookrunner_dir("v1.2.0").exists())

    def test_hookrunner_keeps_only_two_newest_versions(self):
        self.install_fake_curl()
        for n, tag in enumerate(["v1.0.0", "v1.1.0", "v1.2.0"]):
            hr = self.make_signed_hookrunner(tag)
            self.set_rules(hr["rules"])
            result = self.run_install("--hookrunner", tag, extra_env={"CWPILOT_SIGNING_PUBKEY": str(hr["pub"])})
            self.assertEqual(result.returncode, 0, result.stderr)
            # Distinct directory mtimes: retention is by install recency.
            os.utime(self.hookrunner_dir(tag), (1_000_000 + n, 1_000_000 + n))

        names = sorted(p.name for p in self.versions_dir().iterdir())
        self.assertEqual(names, ["hookrunner-v1.1.0", "hookrunner-v1.2.0"])

    def test_cached_version_without_a_sig_gets_it_backfilled_without_redownloading(self):
        self.install_fake_curl()
        release = self.make_signed_release("v2.0.0", content=b"#!/bin/sh\necho genuine\n")
        self.seed_cached_version("v2.0.0", content=release["binary"].read_bytes(), with_sig=False)
        self.set_rules([release["binary_rule"], {"match": f"download/v2.0.0/{ASSET}", "action": "fail",
                                                  "message": "binary must not be re-downloaded"}])

        result = self.run_install("v2.0.0", extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.versions_dir() / "v2.0.0" / "cwpilot.sig").read_bytes(), release["sig"].read_bytes())
        self.assertEqual(len(self.curl_calls()), 1)
        self.assertTrue(self.curl_calls()[0].endswith(".sig"))

    def test_backfill_refuses_a_cached_binary_that_is_not_the_genuine_release(self):
        self.install_fake_curl()
        release = self.make_signed_release("v2.0.0", content=b"#!/bin/sh\necho genuine\n")
        self.seed_cached_version("v2.0.0", content=b"#!/bin/sh\necho tampered\n", with_sig=False)
        self.set_rules([release["binary_rule"]])

        result = self.run_install("v2.0.0", extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature verification failed", result.stderr)
        self.assertFalse((self.versions_dir() / "v2.0.0" / "cwpilot.sig").exists())
        self.assertFalse(self.stable_link().exists(), "a refused binary must not become the stable link")

    def test_embedded_public_key_is_stored_in_versions_dir(self):
        self.install_fake_curl()
        self.set_rules([{"match": "", "action": "fail", "message": "network should not be used"}])
        self.seed_cached_version("v1.2.3")

        result = self.run_install("v1.2.3")

        self.assertEqual(result.returncode, 0, result.stderr)
        stored = self.versions_dir() / "signing.pub"
        self.assertEqual(stored.read_text().strip(), (REPO_ROOT / "signing.pub").read_text().strip(),
                         "stored key must be the one install.sh embeds (kept in sync with signing.pub)")
        self.assertEqual(sorted(p.name for p in self.versions_dir().iterdir()), ["signing.pub", "v1.2.3"])

    def test_override_key_is_never_stored_as_the_trust_root(self):
        self.install_fake_curl()
        hr = self.make_signed_hookrunner("v1.2.0")
        self.set_rules(hr["rules"])

        result = self.run_install("--hookrunner", "v1.2.0", extra_env={"CWPILOT_SIGNING_PUBKEY": str(hr["pub"])})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.versions_dir() / "signing.pub").exists())

    def test_cwpilot_install_keeps_sig_and_does_not_prune_hookrunner(self):
        self.install_fake_curl()
        hr_dir = self.hookrunner_dir("v1.2.0")
        hr_dir.mkdir(parents=True)
        (hr_dir / "hookrunner").write_bytes(b"x")
        self.seed_cached_version("v0.9.0")
        self.stable_link().parent.mkdir(parents=True)
        os.symlink(self.versions_dir() / "v0.9.0" / "cwpilot", self.stable_link())
        release = self.make_signed_release("v2.0.0")
        self.set_rules([release["metadata_rule"], release["binary_rule"], release["download_rule"]])

        result = self.run_install(extra_env={"CWPILOT_SIGNING_PUBKEY": str(release["pub"])})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.versions_dir() / "v2.0.0" / "cwpilot.sig").read_bytes(), release["sig"].read_bytes())
        self.assertTrue((hr_dir / "hookrunner").exists(), "cwpilot retention must not delete hookrunner")


if __name__ == "__main__":
    unittest.main()
