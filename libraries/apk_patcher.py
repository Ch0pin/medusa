"""APK artifact patching. Device installation is a separate operation."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Sequence
import xml.etree.ElementTree as ET
from zipfile import BadZipFile, ZipFile, ZIP_STORED

import requests

if TYPE_CHECKING:
    from libraries.apk_gadget import GadgetConfig


ANDROID = "{http://schemas.android.com/apk/res/android}"
APKTOOL_VERSION = "2.9.2"
APKTOOL_URL = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"
APKTOOL_SHA256 = "831f0ffc97b6f20f511d6183cbf6785464d341aacb0fb7e6f22ef0c7b228911a"
_V1_SIGNATURE = re.compile(r"META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))", re.I)


class PatchError(Exception):
    def __init__(self, stage: str, message: str):
        super().__init__(f"{stage}: {message}")
        self.stage = stage
        self.workspace: Path | None = None


@dataclass(frozen=True)
class SigningConfig:
    keystore: Path
    alias: str = "common"
    # Environment references keep user-provided passwords out of command arguments.
    store_password_env: str | None = None
    key_password_env: str | None = None
    bundled_test_key: bool = True

    def environment(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.bundled_test_key:
            env["MANGO_PATCH_STORE_PASSWORD"] = "password"
            env["MANGO_PATCH_KEY_PASSWORD"] = "password"
        else:
            for name in (self.store_password_env, self.key_password_env):
                if not name or name not in env:
                    raise PatchError("signing configuration", "provide populated --ks-pass-env and --key-pass-env variables")
        return env

    def arguments(self) -> list[str]:
        store = "MANGO_PATCH_STORE_PASSWORD" if self.bundled_test_key else self.store_password_env
        key = "MANGO_PATCH_KEY_PASSWORD" if self.bundled_test_key else self.key_password_env
        return ["--ks", str(self.keystore.expanduser().resolve()), "--ks-key-alias", self.alias,
                "--ks-pass", f"env:{store}", "--key-pass", f"env:{key}"]


@dataclass
class ApkInfo:
    path: Path
    manifest: ET.Element
    package: str
    version: tuple[int, int]
    split: str
    dependencies: set[str] = field(default_factory=set)
    config_for: str = ""


@dataclass
class PatchResult:
    outputs: list[Path]
    package: str
    signer_sha256: tuple[str, ...]
    source_signers: dict[str, tuple[str, ...]]
    tool_versions: dict[str, str]
    workspace: Path | None
    gadget: dict | None = None


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download_apktool(destination: Path) -> None:
    """Install the documented fallback JAR only after checking its release digest."""
    destination = destination.expanduser().absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise PatchError("download", f"destination already exists: {destination}")
    temporary: Path | None = None
    try:
        started = time.monotonic()
        with requests.get(APKTOOL_URL, stream=True, timeout=(10, 30)) as response:
            response.raise_for_status()
            if not response.url.startswith("https://"):
                raise PatchError("download", "the download redirected away from HTTPS")
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".mango-apktool-", delete=False) as stream:
                temporary = Path(stream.name)
                count = 0
                for chunk in response.iter_content(1024 * 1024):
                    count += len(chunk)
                    if count > 128 * 1024 * 1024 or time.monotonic() - started > 180:
                        raise PatchError("download", "download exceeded its size or time limit")
                    stream.write(chunk)
        if sha256(temporary) != APKTOOL_SHA256:
            raise PatchError("download", "Apktool SHA-256 differs from the expected release digest")
        # Do not replace a JAR created by another Mango process during download.
        os.link(temporary, destination)
    except (OSError, requests.RequestException) as exc:
        raise PatchError("download", str(exc)) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_manifest(path: Path) -> ET.Element:
    try:
        with ZipFile(path) as archive:
            seen = set()
            for item in archive.infolist():
                name = item.filename
                if (name in seen or name.startswith("/") or "\\" in name
                        or ".." in PurePosixPath(name).parts or (item.external_attr >> 16) & 0o170000 == 0o120000):
                    raise PatchError("input", f"unsafe or duplicate archive entry in {path}: {name}")
                seen.add(name)
            if archive.getinfo("AndroidManifest.xml").file_size > 16 * 1024 * 1024:
                raise PatchError("manifest", f"manifest exceeds 16 MiB: {path}")
            data = archive.read("AndroidManifest.xml")
        # Androguard is already a Mango dependency; read the actual binary manifest.
        from androguard.core.axml import AXMLPrinter
        printer = AXMLPrinter(data)
        if not printer.is_valid():
            raise PatchError("manifest", f"invalid binary manifest: {path}")
        return ET.fromstring(printer.get_xml())
    except (OSError, BadZipFile, KeyError, ET.ParseError, ValueError) as exc:
        raise PatchError("manifest", f"{path}: {exc}") from exc


def apk_info(path: Path, root: ET.Element) -> ApkInfo:
    try:
        package = root.attrib["package"]
        code = root.attrib[ANDROID + "versionCode"]
        major = root.get(ANDROID + "versionCodeMajor", "0")
        version = tuple(int(value, 16 if value.lower().startswith("0x") else 10) for value in (major, code))
    except (KeyError, ValueError) as exc:
        raise PatchError("manifest", f"missing or invalid package/version in {path}") from exc
    if root.tag != "manifest" or not package:
        raise PatchError("manifest", f"invalid manifest root in {path}")
    dependencies = {node.get(ANDROID + "name", "") for node in root.findall("uses-split")}
    if "" in dependencies:
        raise PatchError("manifest", f"uses-split without a name in {path}")
    return ApkInfo(path, root, package, version, root.get("split", ""), dependencies, root.get("configForSplit", ""))


def validate_apk_set(infos: Sequence[ApkInfo]) -> ApkInfo:
    bases = [info for info in infos if not info.split]
    if len(bases) != 1:
        raise PatchError("split validation", "supply exactly one base APK and its required splits")
    base = bases[0]
    names = {info.split for info in infos}
    if len(names) != len(infos):
        raise PatchError("split validation", "duplicate split identifiers")
    for info in infos:
        if (info.package, info.version) != (base.package, base.version):
            raise PatchError("split validation", f"package or version differs: {info.path}")
        required = info.dependencies | ({info.config_for} if info.config_for else set())
        missing = required - names - {"base"}
        if missing:
            raise PatchError("split validation", f"{info.path.name} needs splits: {', '.join(sorted(missing))}")
        # Newer bundle formats declare required config types on each owner.
        needed_types = {value.strip() for value in info.manifest.get(ANDROID + "requiredSplitTypes", "").split(",") if value.strip()}
        provided_types = set()
        for member in infos:
            if member is info or (member.split and (member.config_for == info.split or (not info.split and member.config_for == "base"))):
                provided_types.update(value.strip() for value in member.manifest.get(ANDROID + "splitTypes", "").split(",") if value.strip())
        if needed_types - provided_types:
            raise PatchError("split validation", f"{info.path.name} is missing required split types: {sorted(needed_types - provided_types)}")
    application = base.manifest.find("application")
    if application is None:
        raise PatchError("manifest", f"base APK has no application element: {base.path}")
    if len(infos) == 1 and (base.manifest.get(ANDROID + "isSplitRequired") == "true"
                            or application.get(ANDROID + "isSplitRequired") == "true"):
        raise PatchError("split validation", "this base requires splits; use patchmultiple with the complete set")
    # Detect cycles among feature dependencies before invoking Apktool.
    visiting, visited = set(), set()
    by_name = {info.split: info for info in infos}
    def visit(name):
        if name in visiting:
            raise PatchError("split validation", "cyclic split dependencies")
        if name in visited or name not in by_name:
            return
        visiting.add(name)
        entry = by_name[name]
        dependencies = entry.dependencies | ({entry.config_for} if entry.config_for else set())
        for dependency in dependencies:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)
    for name in by_name:
        visit(name)
    return base


def set_debuggable(path: Path) -> None:
    try:
        tree = ET.parse(path)
        applications = tree.getroot().findall("application")
        if len(applications) != 1:
            raise PatchError("manifest edit", "expected exactly one application element")
        ET.register_namespace("android", ANDROID[1:-1])
        applications[0].set(ANDROID + "debuggable", "true")
        tree.write(path, encoding="utf-8", xml_declaration=True)
    except (OSError, ET.ParseError) as exc:
        raise PatchError("manifest edit", str(exc)) from exc


def _manifest_shape(node: ET.Element, *, base: bool):
    attrs = dict(node.attrib)
    if base and node.tag == "application":
        attrs.pop(ANDROID + "debuggable", None)
    return node.tag, sorted(attrs.items()), (node.text or "").strip(), [_manifest_shape(child, base=base) for child in node]


def _copy_with_manifest(source: Path, destination: Path, manifest: bytes,
                        additions: dict[str, bytes | Path] | None = None) -> None:
    """Copy original payloads; rebuilding a manifest must not rebuild code/resources."""
    with ZipFile(source) as original, ZipFile(destination, "w") as output:
        if additions and set(additions) & set(original.namelist()):
            raise PatchError("payload assembly", "injected entries would overwrite original payloads")
        output.comment = original.comment
        for item in original.infolist():
            if _V1_SIGNATURE.fullmatch(item.filename):
                continue
            if item.filename == "AndroidManifest.xml":
                output.writestr(copy.copy(item), manifest)
            else:
                with original.open(item) as src, output.open(copy.copy(item), "w") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
        for name, payload in (additions or {}).items():
            if isinstance(payload, Path):
                output.write(payload, name, compress_type=ZIP_STORED)
            else:
                output.writestr(name, payload, compress_type=ZIP_STORED)


def _payloads(path: Path) -> dict[str, tuple[str, int]]:
    with ZipFile(path) as archive:
        result = {}
        for item in archive.infolist():
            if item.filename == "AndroidManifest.xml" or _V1_SIGNATURE.fullmatch(item.filename):
                continue
            with archive.open(item) as stream:
                result[item.filename] = (hashlib.file_digest(stream, "sha256").hexdigest(), item.compress_type)
        return result


def output_paths(inputs: Sequence[Path], output_dir: Path | None = None, *, gadget=False) -> list[Path]:
    suffix = "_gadget.apk" if gadget else "_debuggable.apk"
    outputs = [(output_dir or path.parent) / (path.stem + suffix) for path in inputs]
    if len(set(outputs)) != len(outputs):
        raise PatchError("output", "output names collide; use distinct input filenames")
    for target in outputs:
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise PatchError("output", f"output is not a regular file: {target}")
        if target in inputs or any(target.exists() and os.path.samefile(target, source) for source in inputs):
            raise PatchError("output", f"output aliases an input APK: {target}")
    return outputs


def _publish(staged: Sequence[Path], outputs: Sequence[Path], overwrite: bool) -> None:
    """Prepare on each destination filesystem, then publish with failure rollback."""
    pending, backups, published = {}, {}, []
    try:
        for source, target in zip(staged, outputs):
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink() or (target.exists() and (not overwrite or not target.is_file())):
                raise PatchError("publish", f"output exists or changed: {target}")
            fd, name = tempfile.mkstemp(prefix=".mango-publish-", dir=target.parent)
            os.close(fd)
            pending[target] = Path(name)
            shutil.copyfile(source, name)
            if target.exists():
                fd, backup = tempfile.mkstemp(prefix=".mango-backup-", dir=target.parent)
                os.close(fd)
                backups[target] = Path(backup)
                shutil.copy2(target, backup)
        for target, temporary in pending.items():
            if target in backups:
                os.replace(temporary, target)
            else:
                # A concurrent writer cannot be overwritten without approval.
                os.link(temporary, target)
            published.append(target)
    except BaseException as original_error:
        rollback_errors = []
        for target in reversed(published):
            try:
                if target in backups:
                    backup = backups.pop(target)
                    try:
                        os.replace(backup, target)
                    except OSError:
                        # Keep the only recovery copy if restoration itself fails.
                        rollback_errors.append(f"restore {target} from {backup}")
                else:
                    target.unlink()
            except OSError as exc:
                rollback_errors.append(f"{target}: {exc}")
        if rollback_errors:
            raise PatchError("publication rollback", "; ".join(rollback_errors)) from original_error
        raise
    finally:
        for path in (*pending.values(), *backups.values()):
            path.unlink(missing_ok=True)


class ApkPatcher:
    def __init__(self, apktool: Path, signing: SigningConfig, *, timeout: int = 180,
                 progress: Callable[[str], None] = lambda message: None):
        self.apktool = apktool.expanduser().resolve()
        self.signing = signing
        self.timeout = timeout
        self.progress = progress
        self.versions: dict[str, str] = {}
        self.log: Path | None = None
        self.env = signing.environment()

    def run(self, stage: str, args: Sequence[str], *, allow_failure=False) -> subprocess.CompletedProcess:
        self.progress(stage)
        try:
            result = subprocess.run(list(args), capture_output=True, text=True, errors="replace", timeout=self.timeout,
                                    env=self.env, stdin=subprocess.DEVNULL, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            if self.log:
                with self.log.open("a", encoding="utf-8") as stream:
                    stream.write(f"\n[{stage}] {exc}\n")
                    if isinstance(exc, subprocess.TimeoutExpired):
                        stream.write(f"stdout: {exc.stdout!r}\nstderr: {exc.stderr!r}\n")
            raise PatchError(stage, str(exc)) from exc
        if self.log:
            with self.log.open("a", encoding="utf-8") as stream:
                stream.write(f"\n[{stage}] exit={result.returncode}\n{result.stdout}\n{result.stderr}\n")
        if result.returncode and not allow_failure:
            detail = (result.stderr + "\n" + result.stdout).strip()
            raise PatchError(stage, f"exit {result.returncode}: {detail[-6000:]}")
        return result

    def preflight(self) -> None:
        for tool in ("java", "zipalign", "apksigner"):
            resolved = shutil.which(tool)
            if not resolved:
                raise PatchError("preflight", f"{tool} is missing from PATH")
            setattr(self, tool, resolved)
        if not self.apktool.is_file() or not self.signing.keystore.expanduser().is_file():
            raise PatchError("preflight", "Apktool JAR or signing keystore is missing")
        java = self.run("Java version", [self.java, "-version"])
        self.versions["java"] = (java.stderr or java.stdout).strip().splitlines()[0]
        self.command = [self.java, "-jar", str(self.apktool)]
        version = self.run("Apktool version", self.command + ["--version"]).stdout.strip()
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", version)
        if not match or tuple(map(int, match.groups())) < (2, 9, 2) or int(match[1]) not in (2, 3):
            raise PatchError("preflight", f"unsupported Apktool version: {version}; use 2.9.2+ (2.x or 3.x)")
        self.versions["apktool"] = version
        self.versions["apksigner"] = self.run("apksigner version", [self.apksigner, "version"]).stdout.strip()
        alignment = self.run("zipalign capabilities", [self.zipalign, "-h"], allow_failure=True)
        if "-P" not in alignment.stdout + alignment.stderr:
            raise PatchError("preflight", "zipalign must support -P 16; install recent Android SDK Build Tools")
        self.versions["zipalign"] = f"{self.zipalign} (-P 16 supported)"

    def certificates(self, path: Path, *, required: bool) -> tuple[str, ...]:
        sdk_options = ["--min-sdk-version", str(self.min_sdk)] if hasattr(self, "min_sdk") else []
        result = self.run(f"Verify signature: {path.name}", [self.apksigner, "verify", "--verbose", "--print-certs", *sdk_options, str(path)],
                          allow_failure=not required)
        certs = tuple(sorted(re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})", result.stdout)))
        if result.returncode or not certs:
            if required:
                raise PatchError("signature verification", f"no verified signer certificate: {path}")
            return ()
        return tuple(sorted(value.lower() for value in certs))

    def patch(self, files: Sequence[str | Path], *, output_dir: Path | None = None,
              overwrite: bool = False, keep_resources: bool = False, gadget: GadgetConfig | None = None) -> PatchResult:
        inputs = [Path(file).expanduser().resolve() for file in files]
        if not inputs or len(set(inputs)) != len(inputs) or any(not path.is_file() for path in inputs):
            raise PatchError("input", "supply distinct existing APK files")
        outputs = output_paths(inputs, output_dir.expanduser().resolve() if output_dir else None, gadget=gadget is not None)
        existing = [str(path) for path in outputs if path.exists()]
        if existing and not overwrite:
            raise PatchError("output", "explicit overwrite approval is required: " + ", ".join(existing))
        workspace = Path(tempfile.mkdtemp(prefix="mango-patch-"))
        self.log = workspace / "patch.log"
        result, error = None, None
        try:
            self.preflight()
            # Work from private snapshots so a concurrent source edit cannot mix builds.
            snapshots = []
            for index, source in enumerate(inputs):
                target = workspace / f"input-{index}.apk"
                shutil.copyfile(source, target)
                snapshots.append(target)
            infos = [apk_info(path, read_manifest(path)) for path in snapshots]
            base = validate_apk_set(infos)
            uses_sdk = base.manifest.find("uses-sdk")
            minimum = uses_sdk.get(ANDROID + "minSdkVersion", "1") if uses_sdk is not None else "1"
            try:
                self.min_sdk = int(minimum, 16 if minimum.lower().startswith("0x") else 10)
                if self.min_sdk < 1:
                    raise ValueError("minimum SDK must be positive")
            except ValueError as exc:
                raise PatchError("manifest", f"cannot determine numeric minimum SDK: {minimum}") from exc
            source_signers = {str(source): self.certificates(snapshot, required=len(inputs) > 1)
                              for source, snapshot in zip(inputs, snapshots)}
            if len(inputs) > 1 and len(set(source_signers.values())) != 1:
                raise PatchError("split validation", "input APKs have different signing certificates")
            plan = None
            expected_base = copy.deepcopy(base.manifest)
            if gadget is not None:
                from libraries.apk_gadget import prepare_gadget
                plan = prepare_gadget(self, infos, base, workspace, gadget)
                plan.edit_manifest(expected_base)
            decoded = workspace / "decoded-base"
            framework = workspace / "framework"
            # --no-res + --force-manifest leaves plaintext XML in rebuilt APKs on
            # Apktool 2.9.2. Compile resources privately, then keep only the compiled
            # manifest; _copy_with_manifest restores every original payload.
            self.run("Decode base manifest", self.command + ["d", "--no-src",
                     "-p", str(framework), "-o", str(decoded), str(base.path)])
            if plan:
                tree = ET.parse(decoded / "AndroidManifest.xml")
                plan.edit_manifest(tree.getroot())
                ET.register_namespace("android", ANDROID[1:-1])
                tree.write(decoded / "AndroidManifest.xml", encoding="utf-8", xml_declaration=True)
            else:
                set_debuggable(decoded / "AndroidManifest.xml")
            rebuilt = workspace / "rebuilt-base.apk"
            self.run("Build base manifest", self.command + ["b", "-p", str(framework), "-o", str(rebuilt), str(decoded)])
            with ZipFile(rebuilt) as archive:
                new_manifest = archive.read("AndroidManifest.xml")
            staged, signer_sets = [], []
            for index, info in enumerate(infos):
                unsigned, aligned, signed = [workspace / f"{index}-{suffix}.apk" for suffix in ("unsigned", "aligned", "signed")]
                with ZipFile(info.path) as archive:
                    manifest = new_manifest if info is base else archive.read("AndroidManifest.xml")
                additions = plan.additions if plan and info is base else {}
                expected_payloads = _payloads(info.path)
                for name, payload in additions.items():
                    digest = sha256(payload) if isinstance(payload, Path) else hashlib.sha256(payload).hexdigest()
                    expected_payloads[name] = (digest, ZIP_STORED)
                _copy_with_manifest(info.path, unsigned, manifest, additions)
                self.run(f"Align {inputs[index].name}", [self.zipalign, "-P", "16", "-v", "4", str(unsigned), str(aligned)])
                self.run(f"Sign {inputs[index].name}", [self.apksigner, "sign", *self.signing.arguments(),
                         "--min-sdk-version", str(self.min_sdk), "--v4-signing-enabled", "false", "--out", str(signed), str(aligned)])
                signer_sets.append(self.certificates(signed, required=True))
                self.run(f"Verify alignment: {inputs[index].name}", [self.zipalign, "-c", "-P", "16", "-v", "4", str(signed)])
                result_manifest = read_manifest(signed)
                expected_manifest = expected_base if info is base else info.manifest
                ignore_debug = info is base and plan is None
                if _manifest_shape(expected_manifest, base=ignore_debug) != _manifest_shape(result_manifest, base=ignore_debug):
                    raise PatchError("manifest verification", f"unexpected manifest changes: {inputs[index]}")
                if info is base and plan is None and result_manifest.find("application").get(ANDROID + "debuggable") != "true":
                    raise PatchError("manifest verification", "output is not debuggable")
                if expected_payloads != _payloads(signed):
                    raise PatchError("payload verification", f"code, resources, assets or compression changed: {inputs[index]}")
                staged.append(signed)
            if len(set(signer_sets)) != 1:
                raise PatchError("signature verification", "output signing certificates differ")
            _publish(staged, outputs, overwrite)
            result = PatchResult(outputs, base.package, signer_sets[0], source_signers, dict(self.versions),
                                 workspace if keep_resources else None, plan.details if plan else None)
            return result
        except (Exception, KeyboardInterrupt) as exc:
            error = exc if isinstance(exc, PatchError) else PatchError("patch", "interrupted" if isinstance(exc, KeyboardInterrupt) else str(exc))
            error.workspace = workspace if keep_resources else None
            raise error from (exc if error is not exc else None)
        finally:
            self.log = None
            if not keep_resources:
                try:
                    shutil.rmtree(workspace)
                except OSError as cleanup_error:
                    if result:
                        result.workspace = workspace
                    if error:
                        error.workspace = workspace
                    self.progress(f"Cleanup failed; resources retained at {workspace}: {cleanup_error}")
