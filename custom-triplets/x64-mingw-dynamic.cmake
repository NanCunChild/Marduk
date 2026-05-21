# x64-mingw-dynamic.cmake
#
# Overlay triplet for the Linux→Windows cross-build. Mirrors vcpkg's
# built-in `x64-mingw-dynamic` (community triplet) but applies the same
# onnx static-registration fix as `custom-x64-windows.cmake`, so future
# users that flip MARDUK_BUILD_ZFW=ON in the cross preset still get a
# loadable model.

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

set(VCPKG_ENV_PASSTHROUGH PATH)
set(VCPKG_CMAKE_SYSTEM_NAME MinGW)

# Same patch as the MSVC custom triplet — onnx must not statically
# self-register operator schemas, otherwise onnxruntime double-registers
# and refuses to load any .onnx model.
if(PORT STREQUAL "onnx")
    list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS
        "-DONNX_DISABLE_STATIC_REGISTRATION=ON")
endif()
