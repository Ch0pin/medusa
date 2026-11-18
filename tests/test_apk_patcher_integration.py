"""Opt-in local Android SDK tests; build/patch artifacts only, never install them.

Set MANGO_APK_INTEGRATION=1 and ANDROID_HOME to run. Optional MANGO_APKTOOL_JAR
selects a different Apktool release without replacing the bundled installation.
"""
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from zipfile import ZipFile, ZIP_STORED

from libraries.apk_patcher import ANDROID, ApkPatcher, PatchError, SigningConfig, read_manifest, sha256
from libraries.apk_gadget import GadgetConfig, MARKER, CONFIG, LIBRARY


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("MANGO_APK_INTEGRATION") == "1", "set MANGO_APK_INTEGRATION=1 for local SDK tests")
class RealApkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from loguru import logger
        logger.disable("androguard")
        cls.addClassCleanup(logger.enable, "androguard")
        sdk = Path(os.environ["ANDROID_HOME"])
        cls.tools = Path(shutil.which("apksigner")).parent
        cls.android = sdk / "platforms/android-35/android.jar"
        cls.jar = Path(os.environ.get("MANGO_APKTOOL_JAR", str(ROOT / "dependencies/apktool.jar")))
        cls.signing = SigningConfig(ROOT / "dependencies/common.jks")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mango-sdk-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def run_tool(self, arguments):
        return subprocess.run([str(arg) for arg in arguments], check=True, capture_output=True, text=True,
                              timeout=180, env=self.signing.environment(), stdin=subprocess.DEVNULL)

    def fixture(self, name, *, debug=None, split=None, version=7):
        work = self.root / name
        work.mkdir()
        flag = '' if debug is None else f' android:debuggable="{debug}"'
        split_attr = f' split="{split}"' if split else ''
        xml = (f'<manifest xmlns:android="{ANDROID[1:-1]}" package="test.mango.fixture" '
               f'android:versionCode="{version}"{split_attr}>'
               '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>'
               f'<application android:hasCode="false" android:label="Fixture"{flag}/></manifest>')
        manifest = work / "AndroidManifest.xml"
        manifest.write_text(xml)
        unsigned, output = work / "unsigned.apk", self.root / f"{name}.apk"
        self.run_tool([self.tools / "aapt2", "link", "-I", self.android, "--manifest", manifest, "-o", unsigned])
        with ZipFile(unsigned, "a") as archive:
            archive.writestr("assets/sample.txt", b"same asset contents")
            # Test ZIP alignment/preservation, not native execution.
            archive.writestr("lib/arm64-v8a/libfixture.so", b"alignment fixture", compress_type=ZIP_STORED)
            archive.writestr("META-INF/fixture.kotlin_module", b"keep this metadata")
        aligned = work / "aligned.apk"
        self.run_tool([self.tools / "zipalign", "-P", "16", "4", unsigned, aligned])
        self.run_tool([self.tools / "apksigner", "sign", *self.signing.arguments(),
                       "--v4-signing-enabled", "false", "--out", output, aligned])
        return output

    def test_real_manifest_variants_and_repeat_patch(self):
        for initial in (None, "false", "true"):
            with self.subTest(initial=initial):
                source = self.fixture(f"app {initial}; literal", debug=initial)
                before = sha256(source)
                result = ApkPatcher(self.jar, self.signing).patch([source])
                root = read_manifest(result.outputs[0])
                self.assertEqual(root.find("application").get(ANDROID + "debuggable"), "true")
                self.assertEqual(sha256(source), before)
                self.assertEqual(len(result.signer_sha256), 1)
        # The previous output is itself a valid input, with a fresh output name.
        again = ApkPatcher(self.jar, self.signing).patch(result.outputs)
        self.assertTrue(again.outputs[0].exists())

    def test_real_split_set_and_already_debuggable_base(self):
        base = self.fixture("base", debug="true")
        split = self.fixture("split.en", split="config.en")
        sources = [base, split]
        before = [sha256(path) for path in sources]
        with ZipFile(split) as archive:
            original_split_manifest = archive.read("AndroidManifest.xml")
        result = ApkPatcher(self.jar, self.signing).patch(sources)
        self.assertEqual(len(result.outputs), 2)
        self.assertEqual([sha256(path) for path in sources], before)
        with ZipFile(result.outputs[1]) as archive:
            self.assertEqual(archive.read("AndroidManifest.xml"), original_split_manifest)

    def test_real_mismatched_split_is_rejected_without_outputs(self):
        base = self.fixture("base")
        split = self.fixture("split.en", split="config.en", version=8)
        with self.assertRaisesRegex(PatchError, "package or version differs"):
            ApkPatcher(self.jar, self.signing).patch([base, split])
        self.assertEqual(list(self.root.glob("*_debuggable.apk")), [])

    def test_repository_agent_preserves_real_code_and_resources(self):
        source = ROOT / "dependencies/agent.apk"
        if not source.is_file():
            self.skipTest("optional Medusa agent APK is not installed")
        before = sha256(source)
        result = ApkPatcher(self.jar, self.signing).patch([source], output_dir=self.root)
        self.assertEqual(sha256(source), before)
        self.assertTrue(result.outputs[0].is_file())

    def test_real_gadget_injection_without_custom_application_and_with_splits(self):
        library = os.environ.get("MANGO_GADGET_LIBRARY")
        if not library:
            self.skipTest("set MANGO_GADGET_LIBRARY to a genuine Android arm64 Gadget .so or .so.xz")
        base = self.fixture("gadget-base", debug="false")
        split = self.fixture("gadget-split", split="config.en")
        before = [sha256(path) for path in (base, split)]
        self.assertIsNone(read_manifest(base).find("application").get(ANDROID + "name"))
        settings = GadgetConfig(local_libraries={"arm64-v8a": Path(library)}, port=27043)
        result = ApkPatcher(self.jar, self.signing).patch([base, split], gadget=settings)
        application = read_manifest(result.outputs[0]).find("application")
        self.assertIsNone(application.get(ANDROID + "name"))
        self.assertEqual(application.get(ANDROID + "debuggable"), "false")
        self.assertEqual(application.get(ANDROID + "hasCode"), "true")
        provider = application.find("provider")
        self.assertEqual(provider.get(ANDROID + "name"), result.gadget["provider"])
        self.assertEqual(provider.get(ANDROID + "exported"), "false")
        with ZipFile(result.outputs[0]) as archive:
            config = json.loads(archive.read("lib/arm64-v8a/" + CONFIG))
            self.assertEqual(config["interaction"]["port"], 27043)
            self.assertEqual(config["interaction"]["on_load"], "resume")
            self.assertIn("lib/arm64-v8a/" + LIBRARY, archive.namelist())
            self.assertEqual(json.loads(archive.read(MARKER)), result.gadget)
            from androguard.core.dex import DEX
            loader = DEX(archive.read(result.gadget["dex"]))
            self.assertEqual(loader.get_classes_names(), ["L" + result.gadget["provider"].replace(".", "/") + ";"])
        with ZipFile(result.outputs[1]) as output, ZipFile(split) as original:
            self.assertEqual(output.read("AndroidManifest.xml"), original.read("AndroidManifest.xml"))
            self.assertNotIn(MARKER, output.namelist())
        self.assertEqual([sha256(path) for path in (base, split)], before)
        with self.assertRaisesRegex(PatchError, "already exist"):
            ApkPatcher(self.jar, self.signing).patch(result.outputs, gadget=settings)


if __name__ == "__main__":
    unittest.main()
