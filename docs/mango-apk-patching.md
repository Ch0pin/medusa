# Mango APK patching

`patch` produces a debuggable copy of one standalone APK. `patchmultiple` accepts a base APK and its matching split APKs, patches the base manifest, and signs every member with the selected key. `patch gadget` injects Frida Gadget into either a standalone APK or a base plus its splits. All commands preserve the original input files, and signing options remain optional.

## Commands

At the Mango prompt, these examples assume the checkout is `/Users/ch0pin/Desktop/medusa` and input samples are in `/Users/ch0pin/Desktop/apks`:

```text
patch /Users/ch0pin/Desktop/apks/example.apk
patch "/Users/ch0pin/Desktop/apks/My App.apk" --output-dir /Users/ch0pin/Desktop/apks/patched
patchmultiple /Users/ch0pin/Desktop/apks/base.apk /Users/ch0pin/Desktop/apks/split_config.arm64_v8a.apk /Users/ch0pin/Desktop/apks/split_config.en.apk
patch --help
```

Output names retain the existing convention: `example.apk` becomes `example_debuggable.apk`, beside the input unless `--output-dir` is supplied. Existing output files require confirmation; `--overwrite` explicitly approves replacement. Input/output aliases and symlink outputs are rejected. An already-debuggable base still produces a verified, consistently signed output.

Mango asks whether to keep the extracted resources and stage log when the operation finishes or fails. `--keep-resources` retains them without that question. The printed absolute temporary directory contains `patch.log`, input snapshots and intermediate APKs. Each run owns a new directory; old extracted directories and the former shared `debuggable.apk` are never reused.

## Signing

The default is Medusa's bundled test keystore, `/Users/ch0pin/Desktop/medusa/dependencies/common.jks`, with alias `common`. The command prints the selected keystore and the verified output certificate SHA-256 fingerprint.

For a custom key, set password environment variables **before launching Mango**. The following shell commands prompt privately for the password:

```sh
read -s 'MANGO_KEY_PASSWORD?Keystore password: '
export MANGO_KEY_PASSWORD
/Users/ch0pin/Desktop/medusa/.venv/bin/python /Users/ch0pin/Desktop/medusa/mango.py
```

Then, at the Mango prompt:

```text
patch /Users/ch0pin/Desktop/apks/example.apk --keystore /Users/ch0pin/keys/testing.jks --ks-key-alias testing --ks-pass-env MANGO_KEY_PASSWORD
```

`--key-pass-env` can name a different environment variable for the private-key password. It defaults to `--ks-pass-env`. Password values are passed to `apksigner` through its environment, rather than included in command arguments.

A certificate change prevents updating an existing installation signed by the publisher. Signature-dependent integrations and app integrity checks may also react to repackaging or the debuggable flag. Use a separate test installation where appropriate. Patching performs no device installation, uninstall, restart, or data clearing.

## What is verified

1. Inputs have valid binary manifests. A split set has exactly one base, unique split identifiers, matching package names/version codes and verified matching input signing certificates. Declared feature dependencies, required split types and dependency cycles are checked. A standalone unsigned APK can be patched; its original signing identity is reported as unverified.
2. For debuggable patching, the base application has exactly one `android:debuggable="true"` attribute, including when its previous value was explicitly `false`. Other manifest elements and attributes must remain semantically identical; split manifest bytes remain unchanged. Gadget mode verifies only the explicitly planned additions described below.
3. DEX, resources, assets, native libraries and other non-signature ZIP entries retain their decompressed content hashes and compression methods. The original resource table is preserved, so compiled manifest resource references must remain identical. Original v1 signature records are replaced by the new signature.
4. Every output passes `apksigner verify` using the base application's minimum SDK and `zipalign -c -P 16`. All output signing fingerprints must match. ZIP alignment does not modify the internal ELF alignment of native libraries.
5. The whole set passes validation before any result is published. Publication failures roll back already-published files. A failed rollback preserves the recovery copy and reports its path. File replacement is atomic per APK; a multi-file set is not a single filesystem transaction and cannot guarantee rollback after host power loss.

Declared dependency checks cannot infer optional or undeclared splits. Supply the complete device-appropriate set. Passing archive checks establishes a verified patched artifact; app launch and behavior are separate device tests.

## Tools and download behavior

Java, `apksigner`, and `zipalign` must be available on `PATH`. `zipalign` must support `-P 16` (recent Android SDK Build Tools). Commands use argument arrays, bounded execution and stage-specific error reporting; filenames are never executed by a shell.

The default JAR remains `/Users/ch0pin/Desktop/medusa/dependencies/apktool.jar`. `--apktool /absolute/path/to/apktool.jar` selects another installation. Versions 2.9.2 or newer in the 2.x/3.x series are accepted; the invoked tools and versions are recorded in the stage log. This change was exercised locally with Java 22, Apktool 2.9.2 and SDK Build Tools 35.0.0.

If the default JAR is missing, Mango offers the documented 2.9.2 fallback from the [official release](https://github.com/iBotPeaches/Apktool/releases/tag/v2.9.2). The transfer checks HTTP status, HTTPS, time/size limits and SHA-256 `831f0ffc97b6f20f511d6183cbf6785464d341aacb0fb7e6f22ef0c7b228911a` before installing it. Existing JARs are preserved. No automatic dependency upgrade occurs.

Apktool runs with `--no-src`. Resources are compiled in the private workspace to produce a binary manifest, then the final APK is assembled from the original payloads and the new manifest. The attempted `--no-res --force-manifest` combination left text XML in Apktool 2.9.2's rebuilt APK, so it is not used. See [Apktool options](https://apktool.org/docs/2.x/cli-parameters/), [Android signing verification](https://developer.android.com/tools/apksigner), and [Android ZIP alignment](https://developer.android.com/tools/zipalign).

## Validation

Run the host tests:

```sh
/Users/ch0pin/Desktop/medusa/.venv/bin/python -B -m unittest discover -s /Users/ch0pin/Desktop/medusa/tests -p test_apk_patcher.py -v
```

Run the opt-in SDK integration tests with Android platform 35 and Build Tools available:

```sh
MANGO_APK_INTEGRATION=1 ANDROID_HOME=/Users/ch0pin/Library/Android/sdk /Users/ch0pin/Desktop/medusa/.venv/bin/python -B -m unittest discover -s /Users/ch0pin/Desktop/medusa/tests -p test_apk_patcher_integration.py -v
```

These tests create temporary fixtures, exercise real Apktool/alignment/signing commands, and optionally patch a copy of the installed Medusa agent APK. They never install anything on a device. `MANGO_APKTOOL_JAR` can select an alternate JAR for compatibility testing.

The reusable pipeline is `/Users/ch0pin/Desktop/medusa/libraries/apk_patcher.py`; Mango's prompt adapter is `/Users/ch0pin/Desktop/medusa/libraries/cli/mango_patch.py`.

## Frida Gadget injection

At the Mango prompt:

```text
patch gadget /Users/ch0pin/Desktop/apks/example.apk --abi arm64-v8a
patch gadget /Users/ch0pin/Desktop/apks/base.apk /Users/ch0pin/Desktop/apks/split_config.arm64_v8a.apk --port 27043
patch gadget /Users/ch0pin/Desktop/apks/example.apk --gadget arm64-v8a=/Users/ch0pin/Desktop/gadgets/frida-gadget.so
patch gadget --help
```

Outputs use `_gadget.apk`, and the existing default key and optional signing/output flags apply. Gadget mode preserves the original debuggable flag; add `--debuggable` to enable it explicitly. Every supplied split is re-signed with the same key.

Mango detects native ABIs across the entire input set and requires Gadget coverage for every one. It supports `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`. Java-only apps require `--abi` (repeatable), or local `--gadget ABI=PATH` inputs that identify the intended ABIs. Device ABI detection and installation are separate operator steps.

By default, missing binaries are downloaded from the official Frida release matching the **installed Python Frida client**. `--gadget-version` selects a particular download release. This does not upgrade Frida, Medusa's Java bridge, or any existing dependencies. Each downloaded archive must have a matching SHA-256 digest in the official release metadata before decompression. Releases without such metadata require local binaries. Downloads are bounded; ELF architecture, shared-library type, program headers and LOAD segment bounds are checked.

`--gadget ABI=/absolute/path/to/library.so` accepts a local uncompressed or XZ-compressed Gadget. Repeat it for multiple ABIs. Local library versions are not inferred or claimed as verified; ensure they match the controller you intend to use. Binary hashes and the generated provider details are saved inside the APK at `assets/medusa-gadget.json`.

### Loading and startup

The injector adds a new, non-exported `ContentProvider` with a unique authority and a separate DEX. Its `onCreate()` calls `System.loadLibrary("frida-gadget")`. The existing application/activities and their original DEX files are preserved. This works with Android's default `Application` as well as a custom subclass: it does not depend on overriding the app's `Application.onCreate()` or finding a launcher activity.

Provider initialization normally precedes `Application.onCreate()` in the selected process, after application construction and `attachBaseContext()`. Other providers with the same initialization priority, direct-boot startup and custom loaders can affect coverage. The injected provider uses the application's default process; `--process :worker` can target another declared app process. It does not automatically instrument every process. See the [Android application lifecycle](https://developer.android.com/reference/android/app/Application#onCreate()).

Gadget and its JSON configuration are added under each target ABI as `libfrida-gadget.so` and `libfrida-gadget.config.so`. The manifest enables native-library extraction so they are available together, enables `hasCode` for the loader, and adds the `INTERNET` permission when needed. The final manifest is checked against exactly these planned changes; original payload hashes and compression methods still have to match. Added DEX, library and configuration hashes are verified too. Re-injecting an APK with Mango's marker or existing Gadget filenames is rejected; use its original inputs instead.

The default configuration listens on `127.0.0.1:27042` with `on_load=resume`, allowing the app to start normally. Choose another `--port` when one is already occupied (for example by frida-server). `--on-load wait` intentionally pauses startup until a Frida controller connects. Java loading failures are logged with the `MangoGadget` tag; native Gadget failures still require device diagnostics. See [Frida Gadget configuration](https://frida.re/docs/gadget/).

After installing and launching the patched app on a selected test device, forward the chosen port and connect. Replace `DEVICE_SERIAL` with the actual serial; these are shell commands, not Mango commands:

```sh
adb -s DEVICE_SERIAL forward tcp:27043 tcp:27043
frida -H 127.0.0.1:27043 -n Gadget
```

The example assumes `--port 27043` was used. Successful injection and APK verification establish the artifact; confirming a live Gadget connection establishes runtime loading.

### Additional requirements and tests

The provider compiler requires a JDK with `javac` supporting `--release 8`, Android SDK `d8` beside `apksigner`, and an installed Android platform JAR. Mango discovers the highest numbered platform in that SDK; `--android-jar /absolute/path/android.jar` overrides it. Added DEX loading requires native multidex, so this injector accepts manifest `minSdkVersion >= 21`. It preserves the declared minimum SDK. Native ELF page compatibility depends on the chosen Gadget binary in addition to ZIP alignment.

Run Gadget host tests:

```sh
/Users/ch0pin/Desktop/medusa/.venv/bin/python -B -m unittest discover -s /Users/ch0pin/Desktop/medusa/tests -p test_apk_gadget.py -v
```

To include real Gadget packaging in the SDK integration suite, provide a genuine arm64 Gadget binary:

```sh
MANGO_APK_INTEGRATION=1 ANDROID_HOME=/Users/ch0pin/Library/Android/sdk MANGO_GADGET_LIBRARY=/Users/ch0pin/Desktop/gadgets/frida-gadget.so /Users/ch0pin/Desktop/medusa/.venv/bin/python -B -m unittest discover -s /Users/ch0pin/Desktop/medusa/tests -p test_apk_patcher_integration.py -v
```

The Gadget transformation is `/Users/ch0pin/Desktop/medusa/libraries/apk_gadget.py`. Its tests cover default/custom application manifest preservation, split coverage, architecture checks, malformed binaries, duplicate injection, configuration and the existing patching behavior. Real SDK tests compile the provider DEX, package genuine Gadget binaries, and verify the signed outputs without touching a device.
