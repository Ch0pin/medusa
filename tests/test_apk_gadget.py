"""Gadget transformation checks without downloading tools or touching devices."""
import lzma
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET
from zipfile import ZipFile

from libraries import apk_gadget as gadget
from libraries.apk_patcher import ANDROID, PatchError, apk_info, output_paths, _payloads
from libraries.cli.mango_patch import argument_parser, gadget_options, patch_command
from test_apk_patcher import FakePatcher, fixture_manifest, manifest, write_apk


def elf(abi):
    _, bits, machine = gadget.ABIS[abi]
    data = bytearray(128)
    data[:7] = b"\x7fELF" + bytes((bits, 1, 1))
    struct.pack_into("<HH", data, 16, 3, machine)
    struct.pack_into("<Q" if bits == 2 else "<I", data, 32 if bits == 2 else 28, 64)
    struct.pack_into("<HH", data, 54 if bits == 2 else 42, 56 if bits == 2 else 32, 1)
    struct.pack_into("<I", data, 64, 1)
    struct.pack_into("<Q" if bits == 2 else "<I", data, 96 if bits == 2 else 80, 128)
    return bytes(data)


class GadgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def input(self, abis=(), extra=None):
        file = self.root / (str(len(list(self.root.iterdir()))) + ".apk")
        with ZipFile(file, "w") as archive:
            archive.writestr("AndroidManifest.xml", manifest())
            for abi in abis:
                archive.writestr(f"lib/{abi}/libsample.so", b"original")
            if extra:
                archive.writestr(extra, b"existing")
        return apk_info(file, ET.fromstring(manifest()))

    def plan(self, config=None):
        return gadget.GadgetPlan({}, "re.medusa.gadget.htest.GadgetProvider", "test.mango.gadget",
                                 config or gadget.GadgetConfig(), {})

    def test_provider_does_not_require_or_replace_application_subclass(self):
        for name in (None, "test.ExistingApplication"):
            with self.subTest(name=name):
                root = ET.fromstring(manifest(debug="false"))
                app = root.find("application")
                if name:
                    app.set(ANDROID + "name", name)
                self.plan().edit_manifest(root)
                self.assertEqual(app.get(ANDROID + "name"), name)
                self.assertEqual(app.get(ANDROID + "debuggable"), "false")
                self.assertEqual(app.get(ANDROID + "hasCode"), "true")
                self.assertEqual(app.get(ANDROID + "extractNativeLibs"), "true")
                provider = app.find("provider")
                self.assertEqual(provider.get(ANDROID + "exported"), "false")
                self.assertIsNone(provider.get(ANDROID + "process"))
                self.assertEqual(provider.get(ANDROID + "initOrder"), "2147483647")
                self.assertIn("android.permission.INTERNET", [p.get(ANDROID + "name") for p in root.findall("uses-permission")])

    def test_explicit_process_and_debugging_options(self):
        root = ET.fromstring(manifest())
        self.plan(gadget.GadgetConfig(process=":worker", debuggable=True)).edit_manifest(root)
        self.assertEqual(root.find("application").get(ANDROID + "debuggable"), "true")
        self.assertEqual(root.find("application/provider").get(ANDROID + "process"), ":worker")

    def test_existing_internet_permission_is_preserved_without_duplicates(self):
        root = ET.fromstring(manifest(extra='<uses-permission android:name="android.permission.INTERNET"/>'))
        self.plan().edit_manifest(root)
        self.assertEqual(len(root.findall("uses-permission")), 1)

    def test_native_abis_are_detected_across_the_entire_split_set(self):
        infos = [self.input(("arm64-v8a",)), self.input(("armeabi-v7a",))]
        self.assertEqual(gadget.select_abis(infos, gadget.GadgetConfig()), ("arm64-v8a", "armeabi-v7a"))
        with self.assertRaisesRegex(PatchError, "every native ABI"):
            gadget.select_abis(infos, gadget.GadgetConfig(abis=("arm64-v8a",)))

    def test_java_only_abi_must_be_explicit(self):
        infos = [self.input()]
        with self.assertRaisesRegex(PatchError, "specify a target"):
            gadget.select_abis(infos, gadget.GadgetConfig())
        self.assertEqual(gadget.select_abis(infos, gadget.GadgetConfig(abis=("x86_64",))), ("x86_64",))
        self.assertEqual(gadget.select_abis(infos, gadget.GadgetConfig(local_libraries={"arm64-v8a": Path("local.so")})), ("arm64-v8a",))

    def test_existing_gadget_and_unknown_architecture_are_rejected(self):
        for entry in (gadget.MARKER, "lib/arm64-v8a/" + gadget.LIBRARY, "lib/arm64-v8a/" + gadget.CONFIG):
            with self.subTest(entry=entry), self.assertRaisesRegex(PatchError, "already exist"):
                gadget.select_abis([self.input(extra=entry)], gadget.GadgetConfig())
        with self.assertRaisesRegex(PatchError, "unsupported ABI"):
            gadget.select_abis([self.input(("mips",))], gadget.GadgetConfig())

    def test_elf_architecture_and_truncation_checks(self):
        file = self.root / "gadget.so"
        for abi in gadget.ABIS:
            with self.subTest(abi=abi):
                file.write_bytes(elf(abi))
                gadget.validate_elf(file, abi)
                other = next(name for name in gadget.ABIS if name != abi)
                with self.assertRaises(PatchError):
                    gadget.validate_elf(file, other)
                file.write_bytes(elf(abi)[:100])
                with self.assertRaises(PatchError):
                    gadget.validate_elf(file, abi)

    def test_local_xz_is_expanded_and_version_is_not_guessed(self):
        source = self.root / "input.so.xz"
        source.write_bytes(lzma.compress(elf("arm64-v8a")))
        with patch.object(gadget.requests, "get") as network:
            binaries, records = gadget.gadget_libraries(("arm64-v8a",), gadget.GadgetConfig(local_libraries={"arm64-v8a": source}), self.root, Mock())
        self.assertEqual(binaries["arm64-v8a"].read_bytes(), elf("arm64-v8a"))
        self.assertEqual(records["arm64-v8a"]["version"], "unverified")
        network.assert_not_called()

    def test_download_checksum_failure_prevents_accepting_binary(self):
        response = Mock(url="https://release.example/gadget.so.xz")
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.iter_content.return_value = [b"incorrect"]
        with patch.object(gadget.requests, "get", return_value=response), self.assertRaisesRegex(PatchError, "SHA-256"):
            gadget._download(response.url, self.root / "download", "0" * 64)

    def test_release_without_digest_requires_local_binary(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.json.return_value = {"tag_name": "17.0.0", "assets": [{"name": "frida-gadget-17.0.0-android-arm64.so.xz"}]}
        with patch.object(gadget.requests, "get", return_value=response), self.assertRaisesRegex(PatchError, "provide a local"):
            gadget.gadget_libraries(("arm64-v8a",), gadget.GadgetConfig(version="17.0.0"), self.root, Mock())

    def test_pre_21_and_invalid_configuration_fail_before_compiling(self):
        with self.assertRaisesRegex(PatchError, "native multidex"):
            gadget.prepare_gadget(SimpleNamespace(min_sdk=19), [], None, self.root, gadget.GadgetConfig())
        for config in (gadget.GadgetConfig(port=0), gadget.GadgetConfig(port=65536),
                       gadget.GadgetConfig(on_load="invalid"), gadget.GadgetConfig(process='invalid"process')):
            with self.subTest(config=config), self.assertRaises(PatchError):
                gadget.prepare_gadget(SimpleNamespace(min_sdk=21), [], None, self.root, config)

    def test_gadget_outputs_have_distinct_names(self):
        source = self.root / "app.apk"
        source.touch()
        self.assertEqual(output_paths([source], gadget=True), [self.root / "app_gadget.apk"])

    def test_gadget_pipeline_preserves_original_dex_and_injects_only_declared_entries(self):
        source = self.root / "base.apk"
        write_apk(source, manifest(debug="false"))
        before = _payloads(source)
        plan = self.plan()
        plan.additions = {"classes2.dex": b"compiled loader", "assets/medusa-gadget.json": b"{}"}
        with patch("libraries.apk_gadget.prepare_gadget", return_value=plan), \
                patch("libraries.apk_patcher.read_manifest", side_effect=fixture_manifest):
            result = FakePatcher(self.root).patch([source], gadget=gadget.GadgetConfig())
        after = _payloads(result.outputs[0])
        self.assertEqual({name: after[name] for name in before}, before)
        self.assertEqual(set(after) - set(before), set(plan.additions))
        root = fixture_manifest(result.outputs[0])
        self.assertEqual(root.find("application").get(ANDROID + "debuggable"), "false")
        self.assertIsNotNone(root.find("application/provider"))

    def test_help_and_custom_library_argument(self):
        parser = argument_parser(gadget=True)
        self.assertEqual(parser.prog, "patch gadget")
        self.assertIn("optional signing options", parser.format_help())
        self.assertIn("patch gadget --help", argument_parser().format_help())
        options = parser.parse_args(["/tmp/input.apk", "--gadget", 'arm64-v8a="/tmp/my gadget.so"'])
        self.assertEqual(gadget_options(options).local_libraries, {"arm64-v8a": Path("/tmp/my gadget.so")})
        options.gadget.append("arm64-v8a=/tmp/duplicate.so")
        with self.assertRaises(PatchError):
            gadget_options(options)

    def test_subcommand_routes_split_sets_to_gadget_mode(self):
        files = [self.root / "base.apk", self.root / "split.apk"]
        for file in files:
            file.touch()
        jar = self.root / "tool.jar"
        jar.touch()
        result = SimpleNamespace(workspace=None, package="test", signer_sha256=("digest",), outputs=files,
                                 source_signers={"base": ("digest",)}, gadget={"abis": ["arm64-v8a"], "process": "test", "on_load": "resume"})
        with patch("libraries.cli.mango_patch.ApkPatcher") as patcher:
            patcher.return_value.patch.return_value = result
            returned = patch_command(["gadget", *map(str, files), "--abi", "arm64-v8a"], multiple=False,
                                     apktool=jar, keystore=self.root / "key", ask=Mock(return_value=False), logger=Mock())
            self.assertIsNone(returned)
            self.assertEqual(patcher.return_value.patch.call_args.kwargs["gadget"].abis, ("arm64-v8a",))


if __name__ == "__main__":
    unittest.main()
