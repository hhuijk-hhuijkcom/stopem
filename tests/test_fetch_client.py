"""Seam tests for tools/fetch_client.py (stdlib unittest, no network)."""
import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import fetch_client

# Lines copied verbatim from ClientManifest/steam_client_win64 (v1788652215):
# a file-first block, the bins block, and a nested-block package.
MANIFEST_HEAD = '''"win64"
{
\t"version"\t\t"1788652215"
\t"ostype"\t\t"win10"
\t"tenfoot_images_all"
\t{
\t\t"file"\t\t"tenfoot_images_all.zip.86419c7a56c12dd107b5e0d46f50c8a9b121f3cc"
\t\t"size"\t\t"6582204"
\t}
\t"bins_win64"
\t{
\t\t"file"\t\t"bins_win64.zip.36f5d9202e79ab2aa3e3c5902e84bbd799d31fc0"
\t\t"size"\t\t"63700191"
\t}
\t"steam_win64"
\t{
\t\t"steamrow"
\t\t{
\t\t\t"file"\t\t"steam_win64_steamrow.zip.6f024698857e81681cf673422a8c1a4d06e2be7f"
\t\t\t"size"\t\t"2668385"
\t\t}
\t}
}
'''


class ParseManifestTests(unittest.TestCase):
    def test_version_and_packages(self):
        version, packages = fetch_client.parse_manifest(MANIFEST_HEAD)
        self.assertEqual(version, "1788652215")
        self.assertEqual(
            packages,
            [
                ("tenfoot_images_all",
                 "tenfoot_images_all.zip.86419c7a56c12dd107b5e0d46f50c8a9b121f3cc"),
                ("bins_win64",
                 "bins_win64.zip.36f5d9202e79ab2aa3e3c5902e84bbd799d31fc0"),
                ("steam_win64",
                 "steam_win64_steamrow.zip.6f024698857e81681cf673422a8c1a4d06e2be7f"),
            ],
        )

    def test_space_indented_blocks(self):
        text = MANIFEST_HEAD.replace("\t", "  ")
        version, packages = fetch_client.parse_manifest(text)
        self.assertEqual(version, "1788652215")
        self.assertEqual(len(packages), 3)

    def test_crlf_line_endings(self):
        text = MANIFEST_HEAD.replace("\n", "\r\n")
        version, packages = fetch_client.parse_manifest(text)
        self.assertEqual(version, "1788652215")
        self.assertEqual(len(packages), 3)


class SelectPackagesTests(unittest.TestCase):
    def test_bins_first_then_fallbacks(self):
        P = fetch_client.Package
        packages = [
            P("tenfoot_images_all", "tenfoot_images_all.zip.aaa"),
            P("bins_misc_win64", "bins_misc_win64.zip.bbb"),
            P("bins_win64", "bins_win64.zip.ccc"),
            P("steam_win64", "steam_win64_steamrow.zip.ddd"),
            P("steamrow", "steam_win64_steamrow.zip.ddd"),
            P("bins_cef_win64", "bins_cef_win64.zip.eee"),
        ]
        self.assertEqual(
            fetch_client.select_packages(packages),
            [
                "bins_win64.zip.ccc",
                "bins_misc_win64.zip.bbb",
                "bins_cef_win64.zip.eee",
                "tenfoot_images_all.zip.aaa",
                "steam_win64_steamrow.zip.ddd",
            ],
        )


class ExtractTargetsTests(unittest.TestCase):
    def _make_zip(self, names):
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for n in names:
                z.writestr(n, b"data:" + n.encode())
        return buf.getvalue()

    def test_hit_extracts_by_basename(self):
        data = self._make_zip(["steamclient64.dll", "x/SteamUI.dll", "other.txt"])
        self.assertEqual(
            fetch_client.extract_targets(data, fetch_client.TARGET_DLLS),
            {
                "steamclient64.dll": b"data:steamclient64.dll",
                "SteamUI.dll": b"data:x/SteamUI.dll",
            },
        )

    def test_miss_returns_none(self):
        data = self._make_zip(["steamclient64.dll", "other.txt"])
        self.assertIsNone(fetch_client.extract_targets(data, fetch_client.TARGET_DLLS))


class NeedsPublishTests(unittest.TestCase):
    def test_new_sha_needs_publish(self):
        self.assertTrue(fetch_client.needs_publish(["aa", "bb"], ["aa"]))

    def test_all_published_needs_nothing(self):
        self.assertFalse(fetch_client.needs_publish(["aa", "bb"], ["aa", "bb", "cc"]))


class ResolveKnownTests(unittest.TestCase):
    VERSIONS = {
        "1788652215": {
            "channel": "stable",
            "steamclient64.dll": "aa",
            "SteamUI.dll": "bb",
        }
    }

    def test_known_and_published_returns_shas(self):
        self.assertEqual(
            fetch_client.resolve_known("1788652215", self.VERSIONS, ["aa", "bb", "cc"]),
            {"steamclient64.dll": "aa", "SteamUI.dll": "bb"},
        )

    def test_unknown_version_returns_none(self):
        self.assertIsNone(fetch_client.resolve_known("99999", self.VERSIONS, ["aa", "bb"]))

    def test_known_but_unpublished_returns_none(self):
        self.assertIsNone(fetch_client.resolve_known("1788652215", self.VERSIONS, ["aa"]))


class ChannelManifestTests(unittest.TestCase):
    def test_channel_manifest_urls(self):
        self.assertEqual(
            fetch_client.CHANNEL_MANIFESTS,
            {
                "stable": "https://client-update.fastly.steamstatic.com/steam_client_win64",
                "beta": "https://client-update.fastly.steamstatic.com/steam_client_publicbeta_win64",
            },
        )


class FetchMainTests(unittest.TestCase):
    def _manifest(self, version):
        return (
            '"win64"\n{\n'
            f'\t"version"\t\t"{version}"\n'
            '\t"bins_win64"\n\t{\n'
            f'\t\t"file"\t\t"bins_win64.zip.{version}"\n'
            '\t}\n}\n'
        ).encode()

    def _zip(self, tag):
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("steamclient64.dll", b"sc:" + tag.encode())
            z.writestr("SteamUI.dll", b"sui:" + tag.encode())
        return buf.getvalue()

    def _sha(self, data):
        return hashlib.sha256(data).hexdigest()

    def _run(self, tmp, responses, extra_args):
        import json
        import tempfile

        argv = ["fetch_client.py", "--out", str(tmp / "bins"), *extra_args]
        with mock.patch.object(fetch_client, "fetch_url", side_effect=responses) as m:
            with mock.patch.object(sys, "argv", argv):
                return fetch_client.main(), m

    def test_both_channels_new(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            vfile = tmp / "versions.json"
            code, _ = self._run(
                tmp,
                [self._manifest("111"), self._zip("s111"),
                 self._manifest("222"), self._zip("b222")],
                ["--channels", "stable", "beta", "--versions-file", str(vfile)],
            )
            self.assertEqual(code, 0)
            self.assertEqual((tmp / "bins" / "stable" / "steamclient64.dll").read_bytes(), b"sc:s111")
            self.assertEqual((tmp / "bins" / "beta" / "SteamUI.dll").read_bytes(), b"sui:b222")
            versions = json.loads(vfile.read_text())
            self.assertEqual(
                versions,
                {
                    "111": {
                        "channel": "stable",
                        "steamclient64.dll": self._sha(b"sc:s111"),
                        "SteamUI.dll": self._sha(b"sui:s111"),
                    },
                    "222": {
                        "channel": "beta",
                        "steamclient64.dll": self._sha(b"sc:b222"),
                        "SteamUI.dll": self._sha(b"sui:b222"),
                    },
                },
            )
            stable_bins = json.loads((tmp / "bins" / "stable" / "versions.json").read_text())
            self.assertEqual(stable_bins["channel"], "stable")
            self.assertEqual(stable_bins["version"], "111")

    def test_both_channels_known_skips_download(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            vfile = tmp / "versions.json"
            vfile.write_text(json.dumps({
                "111": {"channel": "stable",
                        "steamclient64.dll": self._sha(b"sc:s111"),
                        "SteamUI.dll": self._sha(b"sui:s111")},
                "222": {"channel": "beta",
                        "steamclient64.dll": self._sha(b"sc:b222"),
                        "SteamUI.dll": self._sha(b"sui:b222")},
            }))
            published = [self._sha(b"sc:s111"), self._sha(b"sui:s111"),
                         self._sha(b"sc:b222"), self._sha(b"sui:b222")]
            code, m = self._run(
                tmp,
                [self._manifest("111"), self._manifest("222")],
                ["--channels", "stable", "beta", "--versions-file", str(vfile),
                 "--published-shas", *published],
            )
            self.assertEqual(code, 2)
            self.assertEqual(m.call_count, 2)
            self.assertFalse((tmp / "bins").exists())

    def test_only_beta_new_fetches_beta(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            vfile = tmp / "versions.json"
            vfile.write_text(json.dumps({
                "111": {"channel": "stable",
                        "steamclient64.dll": self._sha(b"sc:s111"),
                        "SteamUI.dll": self._sha(b"sui:s111")},
            }))
            code, _ = self._run(
                tmp,
                [self._manifest("111"), self._manifest("222"), self._zip("b222")],
                ["--channels", "stable", "beta", "--versions-file", str(vfile),
                 "--published-shas", self._sha(b"sc:s111"), self._sha(b"sui:s111")],
            )
            self.assertEqual(code, 0)
            self.assertFalse((tmp / "bins" / "stable").exists())
            self.assertEqual((tmp / "bins" / "beta" / "steamclient64.dll").read_bytes(), b"sc:b222")
            versions = json.loads(vfile.read_text())
            self.assertEqual(versions["222"]["channel"], "beta")

    def test_unknown_channel_fails(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            code, m = self._run(Path(tmp), [], ["--channels", "canary"])
            self.assertEqual(code, 1)
            self.assertEqual(m.call_count, 0)


if __name__ == "__main__":
    unittest.main()
