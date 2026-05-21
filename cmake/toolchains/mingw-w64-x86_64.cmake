# cmake/toolchains/mingw-w64-x86_64.cmake
#
# CMake toolchain for cross-compiling Marduk from Linux to Windows x64
# using MinGW-w64 (POSIX threads). Designed to be chain-loaded by vcpkg's
# toolchain via VCPKG_CHAINLOAD_TOOLCHAIN_FILE.
#
# Required tools (provided by Debian's `mingw-w64` package or equivalent):
#   x86_64-w64-mingw32-gcc-posix
#   x86_64-w64-mingw32-g++-posix
#   x86_64-w64-mingw32-windres
#   x86_64-w64-mingw32-ar / strip / ld

set(CMAKE_SYSTEM_NAME       Windows)
set(CMAKE_SYSTEM_PROCESSOR  x86_64)

set(_mingw_prefix x86_64-w64-mingw32)

# Some distros suffix the gcc/g++ wrappers with -posix (POSIX threads, the
# only flavour that supports std::thread / std::mutex). Prefer that, fall
# back to the unsuffixed name when running inside images that already
# point /usr/bin/x86_64-w64-mingw32-gcc at the POSIX flavour.
find_program(MARDUK_MINGW_CC
    NAMES ${_mingw_prefix}-gcc-posix ${_mingw_prefix}-gcc
    REQUIRED)
find_program(MARDUK_MINGW_CXX
    NAMES ${_mingw_prefix}-g++-posix ${_mingw_prefix}-g++
    REQUIRED)
find_program(MARDUK_MINGW_RC
    NAMES ${_mingw_prefix}-windres
    REQUIRED)

set(CMAKE_C_COMPILER   "${MARDUK_MINGW_CC}")
set(CMAKE_CXX_COMPILER "${MARDUK_MINGW_CXX}")
set(CMAKE_RC_COMPILER  "${MARDUK_MINGW_RC}")

# Static-link libgcc/libstdc++ so the produced PE files don't drag a
# MinGW redistributable along; matches what vcpkg's x64-mingw-dynamic
# triplet expects of the project itself (third-party libs stay shared).
set(_static_runtime "-static-libgcc -static-libstdc++")
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_static_runtime}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_static_runtime}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_static_runtime}")

# Cross-compile root contains MinGW's own headers/libs.
set(CMAKE_FIND_ROOT_PATH /usr/${_mingw_prefix})

# Programs always come from the host (cmake, ninja, pkg-config, ...).
# Libraries/headers/packages are searched in BOTH the cross sysroot and
# the regular CMake-PREFIX paths so vcpkg's installed tree (e.g.
# build-linux-cross/vcpkg_installed/x64-mingw-dynamic/) is visible to
# find_package and friends. vcpkg manages the actual include/lib paths
# through its imported targets, so this is safe.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
