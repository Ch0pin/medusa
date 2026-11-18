"""Mango's interactive adapter for the offline APK patching service."""
import argparse
from pathlib import Path
import shutil

from cmd2.string_utils import strip_quotes

from libraries.apk_patcher import ApkPatcher, PatchError, SigningConfig, download_apktool, output_paths
from libraries.apk_gadget import ABIS, GadgetConfig


class PatchArguments(argparse.ArgumentParser):
    def error(self, message):
        raise PatchError("arguments", f"{message}; use {self.prog} --help")


def argument_parser(multiple=False, *, gadget=False):
    parser = PatchArguments(
        prog="patch gadget" if gadget else ("patchmultiple" if multiple else "patch"),
        description="Inject Frida Gadget into an APK or split set." if gadget else "Create verified debuggable APK copies.",
        epilog=None if gadget or multiple else "Subcommand: patch gadget --help shows Frida Gadget injection options.",
    )
    parser.add_argument("apks", nargs="+", help="base APK, followed by splits when using patchmultiple")
    parser.add_argument("--output-dir", type=Path, help="directory for the resulting APKs (default: beside each input)")
    parser.add_argument("--apktool", type=Path, help="path to an alternative Apktool JAR")
    bundled_key = Path(__file__).resolve().parents[2] / "dependencies" / "common.jks"
    signing = parser.add_argument_group(
        "optional signing options",
        f"Signing options are optional. By default, Mango uses {bundled_key} (alias: common) "
        "with its bundled password. For a custom keystore, supply --ks-pass-env; "
        "--key-pass-env defaults to the same variable.",
    )
    signing.add_argument("--keystore", type=Path, help="optional custom signing keystore (default: bundled test key)")
    signing.add_argument("--ks-key-alias", default="common", help="optional signing key alias (default: common)")
    signing.add_argument("--ks-pass-env", help="password environment variable; required when --keystore is supplied")
    signing.add_argument("--key-pass-env", help="optional key password environment variable (default: --ks-pass-env)")
    parser.add_argument("--overwrite", action="store_true", help="explicitly approve replacing existing output APKs")
    parser.add_argument("--keep-resources", action="store_true", help="keep private extracted resources and stage diagnostics")
    if gadget:
        group = parser.add_argument_group("Gadget options", "Native ABIs are detected from the APK set. For Java-only apps, select --abi.")
        group.add_argument("--abi", choices=sorted(ABIS), action="append", default=[], help="target ABI; repeat for multiple ABIs")
        group.add_argument("--gadget", action="append", default=[], metavar="ABI=PATH", help="local Gadget .so or .so.xz; repeat per ABI (default: official download)")
        group.add_argument("--gadget-version", help="official download version (default: installed Frida client version)")
        group.add_argument("--port", type=int, default=27042, help="loopback listening port (default: 27042)")
        group.add_argument("--on-load", choices=("resume", "wait"), default="resume", help="start normally or wait for a Frida controller (default: resume)")
        group.add_argument("--process", help="process hosting the loader (default: application's default process)")
        group.add_argument("--android-jar", type=Path, help="Android platform JAR (default: discovered in the SDK)")
        group.add_argument("--debuggable", action="store_true", help="also enable debugging (default: preserve the existing flag)")
    return parser


def gadget_options(options):
    libraries = {}
    for item in options.gadget:
        abi, separator, path = item.partition("=")
        if not separator or abi not in ABIS or not path or abi in libraries:
            raise PatchError("arguments", "use --gadget ABI=/absolute/path/library.so once per ABI")
        libraries[abi] = Path(strip_quotes(path))
    return GadgetConfig(tuple(options.abi), libraries, options.gadget_version, options.port,
                        options.on_load, options.process, options.android_jar, options.debuggable)


def patch_command(arguments, *, multiple, apktool, keystore, ask, logger):
    """Return normally even on failure; cmd2 treats a truthy command result as exit."""
    workspace = None
    keep = False
    try:
        arguments = [strip_quotes(arg) for arg in arguments]
        gadget = not multiple and arguments[:1] == ["gadget"]
        options = argument_parser(multiple, gadget=gadget).parse_args(arguments[1:] if gadget else arguments)
        gadget_config = gadget_options(options) if gadget else None
        keep = options.keep_resources
        if (multiple and len(options.apks) < 2) or (not multiple and not gadget and len(options.apks) != 1):
            raise PatchError("arguments", "use patch for one APK or patchmultiple for a base and its splits")
        files = [Path(path).expanduser().resolve() for path in options.apks]
        if any(not path.is_file() for path in files):
            raise PatchError("input", "every input must be an existing APK file")
        outputs = output_paths(files, options.output_dir.expanduser().resolve() if options.output_dir else None, gadget=gadget)
        existing = [path for path in outputs if path.exists()]
        if existing and not options.overwrite:
            names = "\n".join(str(path) for path in existing)
            if not ask(f"[?] Replace these output APKs?\n{names}", default=False):
                logger.info("[i] Patching cancelled; existing outputs kept.")
                return
            options.overwrite = True
        jar = (options.apktool or Path(apktool)).expanduser().resolve()
        if not jar.is_file():
            if options.apktool:
                raise PatchError("preflight", f"configured Apktool JAR is missing: {jar}")
            if not ask("[?] Download the checksum-verified Apktool fallback?", default=False):
                logger.info("[i] Patching cancelled; Apktool is required.")
                return
            download_apktool(jar)
        signing = SigningConfig(options.keystore or Path(keystore), options.ks_key_alias,
                                options.ks_pass_env, options.key_pass_env or options.ks_pass_env,
                                bundled_test_key=options.keystore is None)
        logger.info(f"[i] Signing key: {signing.keystore.expanduser().resolve()} (alias: {signing.alias})")
        if signing.bundled_test_key:
            logger.info("[i] Bundled test key selected. Changing the certificate prevents updating a publisher-signed installation.")
        patcher = ApkPatcher(jar, signing, progress=lambda stage: logger.info(f"[+] {stage}"))
        result = patcher.patch(files, output_dir=options.output_dir, overwrite=options.overwrite, keep_resources=True, gadget=gadget_config)
        workspace = result.workspace
        if gadget:
            logger.info(f"[+] Verified package: {result.package}; Gadget and loader added, original payloads preserved, signatures and alignment valid.")
            logger.info(f"[i] Gadget ABI(s): {', '.join(result.gadget['abis'])}; process: {result.gadget['process']}; on-load: {result.gadget['on_load']}")
            logger.info(f"[i] After installing and launching, forward device TCP port {options.port} and connect with: frida -H 127.0.0.1:{options.port} -n Gadget")
        else:
            logger.info(f"[+] Verified package: {result.package}; debuggable=true, payloads preserved, signatures and alignment valid.")
        logger.info("[+] Signer SHA-256: " + ", ".join(result.signer_sha256))
        for original, output in zip(files, result.outputs):
            logger.info(f"[+] Original file: {original}")
            logger.info(f"[+] {'Gadget' if gadget else 'Debuggable'} file: {output}")
        if any(not certs for certs in result.source_signers.values()):
            logger.info("[i] The original single APK had no verified signing identity; the output signature is verified.")
    except SystemExit:
        # argparse's --help is local to this command, not Mango's process.
        return
    except PatchError as exc:
        workspace = exc.workspace
        logger.error(f"[!] {exc}")
    except (OSError, ValueError) as exc:
        logger.error(f"[!] Patching failed: {exc}")
    finally:
        if workspace:
            try:
                keep = keep or ask("[?] Do you want to keep the extracted resources and patch log?", default=False)
            except (EOFError, KeyboardInterrupt):
                keep = True
            if keep:
                logger.info(f"[i] Patch resources and diagnostics: {workspace}")
            else:
                try:
                    shutil.rmtree(workspace)
                except OSError as exc:
                    logger.warning(f"[!] Could not remove patch resources at {workspace}: {exc}")
