"""Frida Gadget transformation for Mango's verified APK patching pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import struct
import time
import xml.etree.ElementTree as ET
from zipfile import ZipFile

import requests

from libraries.apk_patcher import ANDROID, PatchError, sha256


# Android ABI -> official Frida release architecture, ELF class, ELF machine.
ABIS = {"armeabi-v7a": ("arm", 1, 40), "arm64-v8a": ("arm64", 2, 183),
        "x86": ("x86", 1, 3), "x86_64": ("x86_64", 2, 62)}
MARKER = "assets/medusa-gadget.json"
LIBRARY = "libfrida-gadget.so"
CONFIG = "libfrida-gadget.config.so"

PROVIDER_SOURCE = """package __PACKAGE__;

public final class GadgetProvider extends android.content.ContentProvider {
    @Override public boolean onCreate() {
        try {
            System.loadLibrary("frida-gadget");
            android.util.Log.i("MangoGadget", "Frida Gadget loaded");
            return true;
        } catch (UnsatisfiedLinkError | SecurityException error) {
            android.util.Log.e("MangoGadget", "Frida Gadget could not load", error);
            return false;
        }
    }
    @Override public android.database.Cursor query(android.net.Uri uri, String[] projection,
            String selection, String[] arguments, String sortOrder) { return null; }
    @Override public String getType(android.net.Uri uri) { return null; }
    @Override public android.net.Uri insert(android.net.Uri uri, android.content.ContentValues values) {
        throw new UnsupportedOperationException();
    }
    @Override public int delete(android.net.Uri uri, String selection, String[] arguments) { return 0; }
    @Override public int update(android.net.Uri uri, android.content.ContentValues values,
            String selection, String[] arguments) { return 0; }
}
"""


@dataclass(frozen=True)
class GadgetConfig:
    abis: tuple[str, ...] = ()
    local_libraries: dict[str, Path] = field(default_factory=dict)
    version: str | None = None
    port: int = 27042
    on_load: str = "resume"
    process: str | None = None
    android_jar: Path | None = None
    debuggable: bool = False


@dataclass
class GadgetPlan:
    additions: dict[str, bytes | Path]
    provider: str
    authority: str
    config: GadgetConfig
    details: dict

    def edit_manifest(self, root: ET.Element) -> None:
        applications = root.findall("application")
        if len(applications) != 1:
            raise PatchError("gadget manifest", "expected exactly one application element")
        application = applications[0]
        # Extract the JSON .config.so alongside Gadget even in release APKs.
        application.set(ANDROID + "extractNativeLibs", "true")
        application.set(ANDROID + "hasCode", "true")
        if self.config.debuggable:
            application.set(ANDROID + "debuggable", "true")
        permissions = [node.get(ANDROID + "name") for node in root.findall("uses-permission")
                       if node.get(ANDROID + "maxSdkVersion") is None]
        if "android.permission.INTERNET" not in permissions:
            root.insert(list(root).index(application), ET.Element("uses-permission", {ANDROID + "name": "android.permission.INTERNET"}))
        attrs = {ANDROID + "name": self.provider, ANDROID + "authorities": self.authority,
                 ANDROID + "exported": "false", ANDROID + "initOrder": "2147483647"}
        if self.config.process:
            attrs[ANDROID + "process"] = self.config.process
        ET.SubElement(application, "provider", attrs)


def select_abis(infos, config: GadgetConfig) -> tuple[str, ...]:
    native = set()
    for info in infos:
        with ZipFile(info.path) as archive:
            for name in archive.namelist():
                if name == MARKER or name.endswith("/" + LIBRARY) or name.endswith("/" + CONFIG):
                    raise PatchError("gadget input", "Gadget files already exist; start from the original APK set")
                match = re.fullmatch(r"lib/([^/]+)/[^/]+\.so", name)
                if match:
                    native.add(match[1])
    requested = set(config.abis)
    unknown = (native | requested | config.local_libraries.keys()) - ABIS.keys()
    if unknown:
        raise PatchError("gadget ABI", f"unsupported ABI(s): {', '.join(sorted(unknown))}")
    if native and requested and requested != native:
        raise PatchError("gadget ABI", f"cover every native ABI in the supplied APK set: {', '.join(sorted(native))}")
    selected = native or requested or set(config.local_libraries)
    if not selected:
        raise PatchError("gadget ABI", "this APK has no native libraries; specify a target, e.g. --abi arm64-v8a")
    if config.local_libraries.keys() - selected:
        raise PatchError("gadget ABI", "local Gadget libraries include an ABI outside the target set")
    return tuple(sorted(selected))


def validate_elf(path: Path, abi: str) -> None:
    try:
        with path.open("rb") as stream:
            header = stream.read(64)
        _, elf_class, machine = ABIS[abi]
        if (len(header) < 64 or header[:4] != b"\x7fELF" or header[4:7] != bytes((elf_class, 1, 1))
                or struct.unpack_from("<HH", header, 16) != (3, machine)):
            raise PatchError("gadget binary", f"expected a little-endian Android {abi} shared library: {path}")
        # Validate the program header table and file-backed LOAD segments as well
        # as the architecture. A truncated download must not become an artifact.
        if elf_class == 2:
            offset, = struct.unpack_from("<Q", header, 32)
            entry_size, count = struct.unpack_from("<HH", header, 54)
            minimum_size = 56
        else:
            offset, = struct.unpack_from("<I", header, 28)
            entry_size, count = struct.unpack_from("<HH", header, 42)
            minimum_size = 32
        size = path.stat().st_size
        if not count or entry_size < minimum_size or offset + entry_size * count > size:
            raise PatchError("gadget binary", f"invalid ELF program headers: {path}")
        loads = 0
        with path.open("rb") as stream:
            for index in range(count):
                stream.seek(offset + index * entry_size)
                entry = stream.read(minimum_size)
                if struct.unpack_from("<I", entry)[0] == 1:
                    loads += 1
                    file_offset = struct.unpack_from("<Q" if elf_class == 2 else "<I", entry, 8 if elf_class == 2 else 4)[0]
                    file_size = struct.unpack_from("<Q" if elf_class == 2 else "<I", entry, 32 if elf_class == 2 else 16)[0]
                    if file_offset + file_size > size:
                        raise PatchError("gadget binary", f"truncated ELF LOAD segment: {path}")
        if not loads:
            raise PatchError("gadget binary", f"ELF has no loadable segments: {path}")
    except OSError as exc:
        raise PatchError("gadget binary", str(exc)) from exc


def _expand(source: Path, destination: Path) -> None:
    try:
        with source.open("rb") as stream:
            compressed = stream.read(6) == b"\xfd7zXZ\x00"
        opener = lzma.open if compressed else open
        count = 0
        with opener(source, "rb") as src, destination.open("xb") as dst:
            while chunk := src.read(1024 * 1024):
                count += len(chunk)
                if count > 256 * 1024 * 1024:
                    raise PatchError("gadget binary", "Gadget exceeds the 256 MiB expanded size limit")
                dst.write(chunk)
    except (lzma.LZMAError, OSError, EOFError) as exc:
        raise PatchError("gadget binary", str(exc)) from exc


def _download(url: str, destination: Path, digest: str) -> None:
    started = time.monotonic()
    try:
        with requests.get(url, stream=True, timeout=(10, 30)) as response:
            response.raise_for_status()
            if not response.url.startswith("https://"):
                raise PatchError("gadget download", "download redirected away from HTTPS")
            count = 0
            with destination.open("xb") as stream:
                for chunk in response.iter_content(1024 * 1024):
                    count += len(chunk)
                    if count > 128 * 1024 * 1024 or time.monotonic() - started > 180:
                        raise PatchError("gadget download", "download exceeded its size or time limit")
                    stream.write(chunk)
        if sha256(destination) != digest:
            raise PatchError("gadget download", "download differs from the official release SHA-256 digest")
    except (requests.RequestException, OSError) as exc:
        raise PatchError("gadget download", str(exc)) from exc


def gadget_libraries(abis, config, workspace, progress):
    missing = set(abis) - config.local_libraries.keys()
    release, version = None, None
    if missing:
        if config.version:
            version = config.version
        else:
            import frida
            version = frida.__version__
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise PatchError("gadget version", "choose an official numeric release with --gadget-version, or provide local binaries")
        progress(f"Resolve official Frida Gadget {version}")
        try:
            with requests.get(f"https://api.github.com/repos/frida/frida/releases/tags/{version}", timeout=(10, 30)) as response:
                response.raise_for_status()
                release = response.json()
            if release.get("draft") or release.get("prerelease") or release.get("tag_name") != version:
                raise PatchError("gadget download", "expected an official non-prerelease Frida release")
        except (requests.RequestException, ValueError) as exc:
            raise PatchError("gadget download", f"{exc}; use --gadget ABI=/absolute/path/to/library.so for offline input") from exc
    binaries, records = {}, {}
    for abi in abis:
        destination = workspace / (abi + "-gadget.so")
        if abi in config.local_libraries:
            source = config.local_libraries[abi].expanduser().resolve()
            _expand(source, destination)
            records[abi] = {"source": "local", "version": "unverified"}
        else:
            name = f"frida-gadget-{version}-android-{ABIS[abi][0]}.so.xz"
            asset = next((asset for asset in release.get("assets", []) if asset.get("name") == name), None)
            if not asset or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", asset.get("digest") or ""):
                raise PatchError("gadget download", f"no release asset with SHA-256 for {abi}; provide a local --gadget binary")
            url = f"https://github.com/frida/frida/releases/download/{version}/{name}"
            if asset.get("browser_download_url") != url:
                raise PatchError("gadget download", "unexpected release asset URL")
            compressed = workspace / name
            progress(f"Download and verify Gadget {version} for {abi}")
            _download(url, compressed, asset["digest"].split(":", 1)[1].lower())
            _expand(compressed, destination)
            records[abi] = {"source": url, "version": version}
        validate_elf(destination, abi)
        records[abi]["sha256"] = sha256(destination)
        binaries[abi] = destination
    return binaries, records


def compiler_paths(apksigner: str, android_jar: Path | None):
    build_tools = Path(apksigner).resolve().parent
    javac = shutil.which("javac")
    d8 = build_tools / ("d8.bat" if os.name == "nt" else "d8")
    if not javac or not d8.is_file():
        raise PatchError("gadget compiler", "install a JDK (javac) and Android SDK Build Tools with d8 beside apksigner")
    if android_jar is None:
        platforms = build_tools.parent.parent / "platforms"
        jars = [path for path in platforms.glob("android-*/android.jar") if re.fullmatch(r"android-\d+", path.parent.name)]
        if not jars:
            raise PatchError("gadget compiler", "install an Android SDK platform or supply --android-jar /absolute/path/android.jar")
        android_jar = max(jars, key=lambda path: int(path.parent.name.split("-")[1]))
    android_jar = android_jar.expanduser().resolve()
    if not android_jar.is_file():
        raise PatchError("gadget compiler", f"Android platform JAR is missing: {android_jar}")
    return javac, str(d8), android_jar


def prepare_gadget(patcher, infos, base, workspace: Path, config: GadgetConfig) -> GadgetPlan:
    if patcher.min_sdk < 21:
        raise PatchError("gadget", "the added DEX requires native multidex: this injector supports APKs with minSdkVersion >= 21")
    if not 1 <= config.port <= 65535 or config.on_load not in ("resume", "wait"):
        raise PatchError("gadget configuration", "choose port 1-65535 and on-load resume or wait")
    if config.process and not re.fullmatch(r":?[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*", config.process):
        raise PatchError("gadget configuration", "invalid Android process name")
    abis = select_abis(infos, config)
    javac, d8, android_jar = compiler_paths(patcher.apksigner, config.android_jar)
    package = "re.medusa.gadget.h" + sha256(base.path)[:16]
    provider = package + ".GadgetProvider"
    authority = base.package + ".medusa.gadget." + sha256(base.path)[:16]
    application = base.manifest.find("application")
    if any(node.get(ANDROID + "name", "").startswith("re.medusa.gadget.") for node in application.findall("provider")):
        raise PatchError("gadget input", "a Mango Gadget provider already exists; use the original APK")
    existing_authorities = {part for node in application.findall("provider") for part in node.get(ANDROID + "authorities", "").split(";")}
    if authority in existing_authorities:
        raise PatchError("gadget input", "generated provider authority already exists")
    with ZipFile(base.path) as archive:
        names = set(archive.namelist())
    indexes = {1 if name == "classes.dex" else int(name[7:-4]) for name in names if re.fullmatch(r"classes(?:[2-9]|[1-9]\d+)?\.dex", name)}
    maximum = max(indexes, default=0)
    if indexes != set(range(1, maximum + 1)):
        raise PatchError("gadget DEX", "non-contiguous multidex numbering requires manual review")
    dex_name = "classes.dex" if not maximum else f"classes{maximum + 1}.dex"
    source = workspace / "GadgetProvider.java"
    source.write_text(PROVIDER_SOURCE.replace("__PACKAGE__", package), encoding="utf-8")
    classes, dex_dir = workspace / "provider-classes", workspace / "provider-dex"
    classes.mkdir()
    dex_dir.mkdir()
    patcher.run("Compile Gadget provider", [javac, "--release", "8", "-classpath", str(android_jar), "-d", str(classes), str(source)])
    class_file = classes / Path(*package.split(".")) / "GadgetProvider.class"
    patcher.run("Build Gadget loader DEX", [d8, "--lib", str(android_jar), "--min-api", str(patcher.min_sdk), "--output", str(dex_dir), str(class_file)])
    dex = dex_dir / "classes.dex"
    from androguard.core.dex import DEX
    compiled = DEX(dex.read_bytes())
    if compiled.get_classes_names() != ["L" + provider.replace(".", "/") + ";"]:
        raise PatchError("gadget DEX", "compiled loader has unexpected class definitions")
    binaries, records = gadget_libraries(abis, config, workspace, patcher.progress)
    settings = json.dumps({"interaction": {"type": "listen", "address": "127.0.0.1", "port": config.port,
                                          "on_port_conflict": "fail", "on_load": config.on_load}}, sort_keys=True).encode("utf-8")
    additions = {dex_name: dex}
    for abi, binary in binaries.items():
        additions[f"lib/{abi}/{LIBRARY}"] = binary
        additions[f"lib/{abi}/{CONFIG}"] = settings
    details = {"provider": provider, "authority": authority, "abis": list(abis), "libraries": records,
               "address": "127.0.0.1", "port": config.port, "on_load": config.on_load,
               "process": config.process or application.get(ANDROID + "process") or base.package,
               "dex": dex_name, "loader_sha256": sha256(dex)}
    additions[MARKER] = json.dumps(details, indent=2, sort_keys=True).encode("utf-8")
    if set(additions) & names:
        raise PatchError("gadget input", "an injected entry would overwrite an existing APK entry")
    return GadgetPlan(additions, provider, authority, config, details)
