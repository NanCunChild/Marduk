# Linux → Windows cross-build

Zero-config workflow for Linux developers who want to iterate on Marduk
without firing up a Windows machine.

## TL;DR

```bash
./scripts/cross-build.sh
```

That's it. The script:

1. Builds a Debian-slim Docker image carrying MinGW-w64 + CMake + Ninja
   (one-time, ~5 minutes).
2. Initialises the `vcpkg/` submodule and bootstraps vcpkg.
3. Runs `cmake --preset linux-cross` followed by `cmake --build`.

Outputs land in `build-linux-cross/bin/Release/`:

| File | Type |
| --- | --- |
| `DNSManagerDll.dll` | Acrylic local DNS proxy controller |
| `WifiPortalDll.dll` | Wi-Fi captive-portal login |
| `MardukElevated.exe` | UAC-elevated helper for the GUI |

The only prerequisite on the host is **Docker**.

## What this can build, what it can't

The cross preset deliberately defaults to `MARDUK_BUILD_GUI=OFF`,
`MARDUK_BUILD_ZFW=OFF` and `MARDUK_BUILD_NETDIAG=OFF`. Each flag has a
concrete reason:

| Target | Cross-build | Why / why not |
| --- | --- | --- |
| `DNSManagerDll` | yes | pure Win32; verified |
| `WifiPortalDll` | yes | cpr + nlohmann_json cross-compile cleanly via vcpkg `x64-mingw-dynamic` |
| `MardukElevated` | yes | UAC manifest is embedded portably via `MardukElevated.rc` |
| `NetworkDiagnosticDll` | **off by default** | Debian 12's mingw-w64 (10.0.0-3) ships `winhttp.h` and `wininet.h` with a duplicate `HTTP_VERSION_INFO` typedef. Works on MSVC and on `llvm-mingw`; fails on Debian's GNU mingw-w64 headers. Re-enable with `-DMARDUK_BUILD_NETDIAG=ON` once you switch to a host distro that patched the headers. |
| `ZfwInteractionDll` | **no** | needs onnxruntime + opencv4 — neither has reliable vcpkg MinGW support today |
| `Marduk` (CLI) | no | depends on Zfw + NetDiag |
| `TestApp` | no | depends on Zfw |
| `MardukGui` | no | needs Qt6, which vcpkg can't reliably cross-compile to MinGW |

You can flip the heavy targets back on at your own risk:

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace marduk-cross-builder \
    cmake --preset linux-cross -DMARDUK_BUILD_NETDIAG=ON
```

If/when vcpkg's MinGW support for those ports stabilises, the preset
defaults will flip.

## Subcommands

```bash
./scripts/cross-build.sh           # full build (default)
./scripts/cross-build.sh configure # only cmake configure
./scripts/cross-build.sh shell     # interactive shell in the container
./scripts/cross-build.sh clean     # remove build-linux-cross/
```

The vcpkg binary cache is kept in a docker volume named
`marduk-vcpkg-cache`; first-time configure pulls/builds the lightweight
deps (cpr, nlohmann-json, tomlplusplus) once, subsequent builds reuse
the cache and finish in seconds.

## Anatomy

| File | Purpose |
| --- | --- |
| `cmake/toolchains/mingw-w64-x86_64.cmake` | CMake toolchain pointing at the POSIX-thread MinGW-w64 compilers |
| `custom-triplets/x64-mingw-dynamic.cmake` | vcpkg overlay triplet (carries the same onnx static-registration patch as the MSVC triplet, in case heavy targets are enabled later) |
| `docker/Dockerfile.cross` | Debian 12 + MinGW-w64 + CMake + Ninja |
| `scripts/cross-build.sh` | One-command wrapper |
| `vcpkg.json` features `gui` / `heavy` | Lets the cross preset opt out of Qt and ONNX/OpenCV during vcpkg install |

## Native Windows builds are unaffected

Everything in this directory is opt-in. `cmake --preset default` on
Windows still produces the full release exactly as before.
