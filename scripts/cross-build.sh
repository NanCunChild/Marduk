#!/usr/bin/env bash
#
# Linux → Windows x64 cross-build for Marduk.
#
# Zero-config entry point. Bootstraps the docker image, the vcpkg
# submodule and the configure step automatically. The only prerequisite
# on the host is `docker` (or podman aliased to docker).
#
# Usage:
#   ./scripts/cross-build.sh                 # full build (Ninja, Release)
#   ./scripts/cross-build.sh configure       # only run cmake configure
#   ./scripts/cross-build.sh shell           # drop into the container
#   ./scripts/cross-build.sh clean           # nuke build-linux-cross/
#
# Environment overrides:
#   MARDUK_CROSS_IMAGE   image tag (default: marduk-cross-builder:latest)
#   MARDUK_CROSS_VOLUME  docker volume name for vcpkg binary cache
#                        (default: marduk-vcpkg-cache)
#   MARDUK_BUILD_GUI     pass-through CMake option (default: OFF here)
#   MARDUK_BUILD_ZFW     pass-through CMake option (default: OFF here)

set -euo pipefail

# ── locate the repo root regardless of where the script is invoked from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE="${MARDUK_CROSS_IMAGE:-marduk-cross-builder:latest}"
VOLUME="${MARDUK_CROSS_VOLUME:-marduk-vcpkg-cache}"

cmd="${1:-build}"

# ── helpers ─────────────────────────────────────────────────────────
log()  { printf '\033[1;36m[cross-build]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[cross-build]\033[0m %s\n' "$*" >&2; exit 1; }

ensure_docker() {
    command -v docker >/dev/null 2>&1 \
        || fail "docker not found. Install Docker Engine first."
}

ensure_image() {
    if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
        log "Building cross-build image (${IMAGE}) — first time only..."
        docker build \
            -t "${IMAGE}" \
            -f "${REPO_ROOT}/docker/Dockerfile.cross" \
            "${REPO_ROOT}"
    fi
}

ensure_volume() {
    if ! docker volume inspect "${VOLUME}" >/dev/null 2>&1; then
        log "Creating vcpkg binary-cache volume (${VOLUME})..."
        docker volume create "${VOLUME}" >/dev/null
    fi
}

# Run a command inside the cross-build container, with the repo bind-
# mounted at /workspace and the binary cache mounted as a volume.
run_in_container() {
    local user_arg=()
    # Avoid root-owning files on the host when the host user isn't root.
    if [[ -n "${SUDO_UID:-}" || "$(id -u)" -ne 0 ]]; then
        user_arg=(--user "$(id -u):$(id -g)" -e HOME=/tmp)
    fi
    docker run --rm -it \
        "${user_arg[@]}" \
        -v "${REPO_ROOT}:/workspace" \
        -v "${VOLUME}:/vcpkg-cache" \
        -w /workspace \
        -e VCPKG_DEFAULT_BINARY_CACHE=/vcpkg-cache \
        -e VCPKG_DISABLE_METRICS=1 \
        "${IMAGE}" \
        bash -ceu "$1"
}

# ── 1. fetch vcpkg submodule if missing ────────────────────────────
ensure_vcpkg_checked_out() {
    if [[ ! -f "${REPO_ROOT}/vcpkg/bootstrap-vcpkg.sh" ]]; then
        log "vcpkg submodule not initialised — running git submodule update..."
        if ! command -v git >/dev/null 2>&1; then
            fail "git not found on the host (needed for submodule init). \
Install git, or run: docker run ... git submodule update --init --recursive"
        fi
        (cd "${REPO_ROOT}" && git submodule update --init --recursive)
    fi
}

# ── 2. bootstrap vcpkg inside the container if needed ──────────────
ensure_vcpkg_bootstrapped() {
    if [[ ! -x "${REPO_ROOT}/vcpkg/vcpkg" ]]; then
        log "Bootstrapping vcpkg (Linux) inside the container..."
        run_in_container '
            cd vcpkg
            ./bootstrap-vcpkg.sh -disableMetrics
        '
    fi
}

# ── 3. dispatch ─────────────────────────────────────────────────────
case "${cmd}" in
    build|"")
        ensure_docker
        ensure_image
        ensure_volume
        ensure_vcpkg_checked_out
        ensure_vcpkg_bootstrapped
        log "Configuring (cmake --preset linux-cross)..."
        run_in_container 'cmake --preset linux-cross'
        log "Building (cmake --build --preset linux-cross)..."
        run_in_container 'cmake --build --preset linux-cross --parallel'
        log "Done. Output: build-linux-cross/bin/Release/"
        ls -la "${REPO_ROOT}/build-linux-cross/bin/Release/" 2>/dev/null || true
        ;;
    configure)
        ensure_docker
        ensure_image
        ensure_volume
        ensure_vcpkg_checked_out
        ensure_vcpkg_bootstrapped
        run_in_container 'cmake --preset linux-cross'
        ;;
    shell)
        ensure_docker
        ensure_image
        ensure_volume
        ensure_vcpkg_checked_out
        run_in_container 'exec bash'
        ;;
    clean)
        log "Removing build-linux-cross/ ..."
        rm -rf "${REPO_ROOT}/build-linux-cross"
        log "Done. (Use 'docker volume rm ${VOLUME}' to wipe the vcpkg cache too.)"
        ;;
    *)
        cat >&2 <<EOF
Usage: $0 [build|configure|shell|clean]

  build       Configure + build (default).
  configure   Only run cmake configure.
  shell       Start an interactive shell in the cross-build container.
  clean       Remove build-linux-cross/.

EOF
        exit 1
        ;;
esac
