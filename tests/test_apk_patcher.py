"""Patcher correctness and failure isolation, with no connected devices."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET
from zipfile import ZipFile, ZIP_STORED

from libraries import apk_patcher as subject
from libraries.cli.mango_patch import patch_command


def manifest(*, debug=None, package="test.mango", version="1", split="", dependency="", config="", extra=""):
    attributes = f' split="{split}"' if split else ""
    if config:
        attributes += f' configForSplit="{config}"'
    flag = '' if debug is None else f' android:debuggable="{debug}"'
    dep = f'<uses-split android:name="{dependency}" />' if dependency else ''
    return (f'<manifest xmlns:android="{subject.ANDROID[1:-1]}" package="{package}" '
            f'android:versionCode="{version}"{attributes}>{dep}<application{flag} />{extra}</manifest>')


def write_apk(path, xml):
    with ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", xml)
        archive.writestr("classes.dex", b"unchanged DEX bytes")
        archive.writestr("resources.arsc", b"unchanged resource table")
        archive.writestr("assets/message.txt", b"preserve this asset")
        archive.writestr("lib/arm64-v8a/libtest.so", b"native bytes", compress_type=ZIP_STORED)
        archive.writestr("META-INF/library.kotlin_module", b"preserve non-signature metadata")
        archive.writestr("META-INF/OLD.SF", b"old signature")


def fixture_manifest(path):
    with ZipFile(path) as archive:
        return ET.fromstring(archive.read("AndroidManifest.xml"))


class FakePatcher(subject.ApkPatcher):
    """Model only external tool effects; execute the real orchestration/verification."""
    def __init__(self, root, failure=None, mutate=None):
        super().__init__(root / "apktool.jar", subject.SigningConfig(root / "common.jks"))
        self.steps = []
        self.failure = failure
        self.mutate = mutate

    def preflight(self):
        self.command = ["apktool"]
        self.zipalign, self.apksigner = "zipalign", "apksigner"
        self.manifest_flag = "--force-manifest"

    def run(self, stage, args, **kwargs):
        self.steps.append(stage)
        if self.failure and stage.startswith(self.failure):
            raise subject.PatchError(stage, "simulated failure")
        output = ""
        if args[0] == "apktool" and args[1] == "d":
            destination = Path(args[args.index("-o") + 1])
            destination.mkdir()
            with ZipFile(args[-1]) as archive:
                (destination / "AndroidManifest.xml").write_bytes(archive.read("AndroidManifest.xml"))
        elif args[0] == "apktool" and args[1] == "b":
            with ZipFile(args[args.index("-o") + 1], "w") as archive:
                archive.write(Path(args[-1]) / "AndroidManifest.xml", "AndroidManifest.xml")
        elif args[0] == "zipalign" and "-c" not in args:
            shutil.copyfile(args[-2], args[-1])
        elif args[:2] == ["apksigner", "sign"]:
            destination = Path(args[args.index("--out") + 1])
            shutil.copyfile(args[-1], destination)
            if self.mutate:
                self.mutate(destination)
        elif args[:2] == ["apksigner", "verify"]:
            output = "Signer #1 certificate SHA-256 digest: " + "a" * 64
        return subprocess.CompletedProcess(args, 0, output, "")


class PatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def info(self, **kwargs):
        return subject.apk_info(self.root / (kwargs.get("split", "base") + ".apk"), ET.fromstring(manifest(**kwargs)))

    def test_debug_attribute_is_set_once_and_other_attributes_survive(self):
        for initial in (None, "false", "true"):
            with self.subTest(initial=initial):
                file = self.root / "AndroidManifest.xml"
                original = manifest(debug=initial).replace("<application", '<application android:label="hello"')
                file.write_text(original)
                subject.set_debuggable(file)
                subject.set_debuggable(file)
                application = ET.parse(file).getroot().find("application")
                self.assertEqual(application.get(subject.ANDROID + "debuggable"), "true")
                self.assertEqual(application.get(subject.ANDROID + "label"), "hello")
                self.assertEqual(file.read_text().count('debuggable="true"'), 1)

    def test_alternative_android_namespace_prefix_is_supported(self):
        file = self.root / "AndroidManifest.xml"
        file.write_text(manifest(debug="false").replace("xmlns:android", "xmlns:a").replace("android:", "a:"))
        subject.set_debuggable(file)
        self.assertEqual(ET.parse(file).find("application").get(subject.ANDROID + "debuggable"), "true")

    def test_missing_or_duplicate_application_is_rejected(self):
        for application in ("", "<application/><application/>"):
            file = self.root / "AndroidManifest.xml"
            file.write_text(f"<manifest>{application}</manifest>")
            with self.assertRaises(subject.PatchError):
                subject.set_debuggable(file)

    def test_matching_split_set_is_accepted(self):
        base = self.info()
        self.assertIs(subject.validate_apk_set([base, self.info(split="feature"), self.info(split="config.en", config="feature")]), base)

    def test_inconsistent_or_incomplete_split_sets_are_rejected(self):
        examples = [
            [self.info(split="config.en")],
            [self.info(), self.info()],
            [self.info(), self.info(split="config.en", version="2")],
            [self.info(), self.info(split="config.en", package="other.app")],
            [self.info(), self.info(split="feature", dependency="absent")],
            [self.info(), self.info(split="config.en", config="absent")],
            [self.info(), self.info(split="a", dependency="b"), self.info(split="b", dependency="a")],
        ]
        for infos in examples:
            with self.subTest(infos=infos), self.assertRaises(subject.PatchError):
                subject.validate_apk_set(infos)

    def test_required_split_flag_and_types(self):
        base = self.info()
        base.manifest.find("application").set(subject.ANDROID + "isSplitRequired", "true")
        with self.assertRaises(subject.PatchError):
            subject.validate_apk_set([base])
        config = self.info(split="config.arm64")
        base.manifest.set(subject.ANDROID + "requiredSplitTypes", "base__abi")
        with self.assertRaises(subject.PatchError):
            subject.validate_apk_set([base, config])
        config.manifest.set(subject.ANDROID + "splitTypes", "base__abi")
        subject.validate_apk_set([base, config])

    def test_non_signature_payloads_and_compression_survive_repack(self):
        original, result = self.root / "source.apk", self.root / "out.apk"
        write_apk(original, manifest())
        subject._copy_with_manifest(original, result, manifest(debug="true").encode())
        self.assertEqual(subject._payloads(original), subject._payloads(result))
        with ZipFile(result) as archive:
            self.assertNotIn("META-INF/OLD.SF", archive.namelist())
            self.assertIn("META-INF/library.kotlin_module", archive.namelist())

    def test_success_and_already_debuggable_both_produce_verified_outputs(self):
        for debug in (None, "false", "true"):
            with self.subTest(debug=debug):
                original = self.root / f"My app {debug}; literal.apk"
                write_apk(original, manifest(debug=debug))
                digest = subject.sha256(original)
                patcher = FakePatcher(self.root)
                with patch.object(subject, "read_manifest", side_effect=fixture_manifest):
                    result = patcher.patch([original])
                self.assertEqual(subject.sha256(original), digest)
                self.assertTrue(result.outputs[0].is_file())
                self.assertEqual(fixture_manifest(result.outputs[0]).find("application").get(subject.ANDROID + "debuggable"), "true")
                self.assertIsNone(result.workspace)

    def test_failure_at_each_stage_preserves_existing_output_and_original(self):
        original = self.root / "base.apk"
        write_apk(original, manifest())
        digest = subject.sha256(original)
        output = self.root / "base_debuggable.apk"
        output.write_bytes(b"previous successful output")
        stages = ("Decode base", "Build base", "Align base", "Sign base", "Verify signature: 0-signed", "Verify alignment")
        for stage in stages:
            with self.subTest(stage=stage), patch.object(subject, "read_manifest", side_effect=fixture_manifest):
                with self.assertRaises(subject.PatchError):
                    FakePatcher(self.root, failure=stage).patch([original], overwrite=True)
                self.assertEqual(output.read_bytes(), b"previous successful output")
                self.assertEqual(subject.sha256(original), digest)

    def test_payload_and_manifest_corruption_are_detected_before_publish(self):
        original = self.root / "base.apk"
        write_apk(original, manifest())
        def mutate(path):
            with ZipFile(path, "a") as archive:
                archive.writestr("unexpected-new-resource", b"unwanted")
        with patch.object(subject, "read_manifest", side_effect=fixture_manifest), self.assertRaisesRegex(subject.PatchError, "payload verification"):
            FakePatcher(self.root, mutate=mutate).patch([original])
        self.assertFalse((self.root / "base_debuggable.apk").exists())
        def mutate_manifest(path):
            temp = path.with_suffix(".replaced")
            subject._copy_with_manifest(path, temp, manifest(debug="true", package="changed.package").encode())
            temp.replace(path)
        with patch.object(subject, "read_manifest", side_effect=fixture_manifest), self.assertRaisesRegex(subject.PatchError, "manifest verification"):
            FakePatcher(self.root, mutate=mutate_manifest).patch([original])

    def test_split_failure_never_publishes_partial_set(self):
        base, split = self.root / "base.apk", self.root / "split.en.apk"
        write_apk(base, manifest(debug="true"))
        write_apk(split, manifest(split="config.en"))
        with patch.object(subject, "read_manifest", side_effect=fixture_manifest), self.assertRaises(subject.PatchError):
            FakePatcher(self.root, failure="Sign split.en").patch([base, split])
        self.assertFalse((self.root / "base_debuggable.apk").exists())
        self.assertFalse((self.root / "split.en_debuggable.apk").exists())

    def test_split_success_preserves_split_manifest_and_signs_every_member(self):
        base, split = self.root / "base.apk", self.root / "split.en.apk"
        write_apk(base, manifest(debug="true"))
        write_apk(split, manifest(split="config.en"))
        patcher = FakePatcher(self.root)
        with patch.object(subject, "read_manifest", side_effect=fixture_manifest):
            result = patcher.patch([base, split])
        self.assertEqual(len(result.outputs), 2)
        self.assertEqual(sum(stage.startswith("Sign ") for stage in patcher.steps), 2)
        self.assertEqual(ET.tostring(fixture_manifest(split)), ET.tostring(fixture_manifest(result.outputs[1])))

    def test_output_overwrite_requires_approval(self):
        source = self.root / "base.apk"
        write_apk(source, manifest())
        (self.root / "base_debuggable.apk").write_bytes(b"keep")
        patcher = FakePatcher(self.root)
        with self.assertRaisesRegex(subject.PatchError, "approval"):
            patcher.patch([source])
        self.assertEqual(patcher.steps, [])

    def test_output_aliases_and_symlinks_are_rejected(self):
        first, second = self.root / "base.apk", self.root / "base_debuggable.apk"
        first.touch()
        second.touch()
        with self.assertRaises(subject.PatchError):
            subject.output_paths([first, second])
        second.unlink()
        second.symlink_to(first)
        with self.assertRaises(subject.PatchError):
            subject.output_paths([first])
        second.unlink()
        os.link(first, second)
        with self.assertRaises(subject.PatchError):
            subject.output_paths([first])

    def test_publish_rolls_back_overwrites_if_later_file_fails(self):
        sources, outputs = [], []
        for index in range(2):
            source, output = self.root / f"source{index}", self.root / f"out{index}"
            source.write_bytes(b"new")
            output.write_bytes(b"old")
            sources.append(source)
            outputs.append(output)
        replace = os.replace
        def fail_second(source, target):
            if target == outputs[1]:
                raise OSError("publication failure")
            return replace(source, target)
        with patch.object(subject.os, "replace", side_effect=fail_second), self.assertRaises(OSError):
            subject._publish(sources, outputs, True)
        self.assertEqual([path.read_bytes() for path in outputs], [b"old", b"old"])
        self.assertEqual(list(self.root.glob(".mango-*")), [])

    def test_publish_does_not_overwrite_concurrently_created_output(self):
        source, output = self.root / "staged", self.root / "output"
        source.write_bytes(b"new")
        link = os.link
        def race(src, dst):
            Path(dst).write_bytes(b"another writer")
            return link(src, dst)
        with patch.object(subject.os, "link", side_effect=race), self.assertRaises(FileExistsError):
            subject._publish([source], [output], False)
        self.assertEqual(output.read_bytes(), b"another writer")

    def test_failed_rollback_keeps_recovery_copy(self):
        inputs, outputs = [], []
        for index in range(2):
            source, output = self.root / f"source{index}", self.root / f"out{index}"
            source.write_bytes(b"new")
            output.write_bytes(b"old")
            inputs.append(source)
            outputs.append(output)
        replace = os.replace
        def fail(src, dst):
            if dst == outputs[1] or str(Path(src).name).startswith(".mango-backup-"):
                raise OSError("disk unavailable")
            return replace(src, dst)
        with patch.object(subject.os, "replace", side_effect=fail), self.assertRaisesRegex(subject.PatchError, "rollback"):
            subject._publish(inputs, outputs, True)
        backups = list(self.root.glob(".mango-backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"old")

    def test_external_commands_are_argument_lists_and_fail_with_stage(self):
        patcher = subject.ApkPatcher(self.root / "tool.jar", subject.SigningConfig(self.root / "key.jks"))
        with patch.object(subject.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "bad APK")) as run:
            with self.assertRaisesRegex(subject.PatchError, "decode: exit 1: bad APK"):
                patcher.run("decode", ["java", "a path; with spaces"])
            self.assertEqual(run.call_args.args[0], ["java", "a path; with spaces"])
            self.assertFalse(run.call_args.kwargs["shell"])
        with patch.object(subject.subprocess, "run", side_effect=subprocess.TimeoutExpired(["java"], 1)):
            with self.assertRaisesRegex(subject.PatchError, "decode"):
                patcher.run("decode", ["java"])

    def test_custom_key_requires_environment_passwords(self):
        config = subject.SigningConfig(self.root / "key.jks", bundled_test_key=False)
        with self.assertRaises(subject.PatchError):
            config.environment()
        config = subject.SigningConfig(self.root / "key.jks", "alias", "MANGO_TEST_PASSWORD", "MANGO_TEST_PASSWORD", False)
        with patch.dict(os.environ, MANGO_TEST_PASSWORD="private-value"):
            self.assertEqual(config.environment()["MANGO_TEST_PASSWORD"], "private-value")
            self.assertNotIn("private-value", " ".join(config.arguments()))

    def test_download_validates_checksum_and_cleans_failed_download(self):
        destination = self.root / "apktool.jar"
        response = Mock(url="https://release.example/apktool.jar")
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.iter_content.return_value = [b"release"]
        with patch.object(subject.requests, "get", return_value=response), patch.object(subject, "APKTOOL_SHA256", "0" * 64):
            with self.assertRaisesRegex(subject.PatchError, "SHA-256"):
                subject.download_apktool(destination)
        self.assertEqual(list(self.root.iterdir()), [])
        response.iter_content.return_value = [b"release"]
        with patch.object(subject.requests, "get", return_value=response), patch.object(subject, "APKTOOL_SHA256", hashlib.sha256(b"release").hexdigest()):
            subject.download_apktool(destination)
        self.assertEqual(destination.read_bytes(), b"release")

    def test_cli_quoted_paths_and_resource_cleanup(self):
        source = self.root / "my app.apk"
        source.touch()
        jar = self.root / "tool.jar"
        jar.touch()
        workspace = self.root / "resources"
        workspace.mkdir()
        result = SimpleNamespace(workspace=workspace, package="test.mango", signer_sha256=("a" * 64,),
                                 outputs=[self.root / "my app_debuggable.apk"], source_signers={str(source): ("a" * 64,)})
        with patch("libraries.cli.mango_patch.ApkPatcher") as cls:
            cls.return_value.patch.return_value = result
            returned = patch_command([f'"{source}"'], multiple=False, apktool=jar, keystore=self.root / "key",
                                     ask=Mock(return_value=False), logger=Mock())
            self.assertIsNone(returned)
            self.assertEqual(cls.return_value.patch.call_args.args[0], [source.resolve()])
            self.assertFalse(workspace.exists())

    def test_cli_declined_download_stops_before_running_tools(self):
        source = self.root / "base.apk"
        source.touch()
        with patch("libraries.cli.mango_patch.ApkPatcher") as cls, patch("libraries.cli.mango_patch.download_apktool") as download:
            patch_command([str(source)], multiple=False, apktool=self.root / "missing.jar", keystore=self.root / "key",
                          ask=Mock(return_value=False), logger=Mock())
            cls.assert_not_called()
            download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
