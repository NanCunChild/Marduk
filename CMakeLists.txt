cmake_minimum_required(VERSION 3.21)

# ───────────────────────────────────────────────────────────────────
# vcpkg toolchain: 必须在 project() 之前注入
# 命令行 -DCMAKE_TOOLCHAIN_FILE=... 或 CMakePresets 优先；
# 否则回退到仓库内子模块 vcpkg/。
# ───────────────────────────────────────────────────────────────────
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE
            "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "vcpkg toolchain file")
    endif()
endif()

# 自定义 triplet —— 修复 onnxruntime 在 vcpkg 默认配置下的 schema 重复注册。
# 命令行/preset 没指定时回退到仓库内的 custom-triplets。
if(NOT DEFINED VCPKG_OVERLAY_TRIPLETS)
    set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_CURRENT_SOURCE_DIR}/custom-triplets"
        CACHE STRING "vcpkg overlay triplets")
endif()
if(NOT DEFINED VCPKG_TARGET_TRIPLET AND CMAKE_HOST_WIN32)
    set(VCPKG_TARGET_TRIPLET "custom-x64-windows"
        CACHE STRING "vcpkg target triplet")
endif()

project(Marduk
    VERSION 2.0.0
    DESCRIPTION "Xidian campus network diagnostic tool"
    LANGUAGES CXX
)

# 仅 Windows 目标平台（无论是 MSVC native 还是 Linux→MinGW 交叉，
# CMAKE_SYSTEM_NAME 都是 Windows，因此 WIN32 == TRUE）
if(NOT WIN32)
    message(FATAL_ERROR
        "Marduk targets Windows only. "
        "On Linux, use the 'linux-cross' preset (MinGW-w64) instead.")
endif()

# RC 仅在 Windows 目标上启用（MSVC: rc.exe，MinGW: windres）。
# 给一个 if(WIN32) 防御层，方便单元/语法测试在 Linux 上临时跳过 fatal。
if(WIN32)
    enable_language(RC)
endif()

# ───────────────────────────────────────────────────────────────────
# 全局编译/链接选项
# ───────────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# DLL 导出宏 (DNSMANAGERDLL_EXPORTS 等) 的自动定义依赖目标名 ==
# 工程名 + "_EXPORTS"，不要改目标名。
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)

# 全局宏：与原 .vcxproj/Directory.Build.props 保持一致
# 注意：WIN32_LEAN_AND_MEAN 故意不在这里全局定义，因为各 DLL 的 framework.h
# 已自行 #define 它（那是 VS 默认生成的模式），而 Marduk.exe / MardukGui 需要
# shellapi.h 等被 LEAN_AND_MEAN 排除的头——全局定义会导致编译失败。
add_compile_definitions(
    UNICODE
    _UNICODE
    NOMINMAX
    _WINSOCK_DEPRECATED_NO_WARNINGS
)

# ── MSVC（Windows 原生构建）──
if(MSVC)
    add_compile_options(
        /utf-8           # 源文件 UTF-8（原 Directory.Build.props 全局选项）
        /permissive-     # ConformanceMode=true
        /W3              # WarningLevel=Level3
        /MP              # 并行编译
        /sdl             # SDLCheck=true
        /Zc:__cplusplus  # 让 __cplusplus 反映真实 C++ 版本
    )
    add_compile_options(
        $<$<CONFIG:Release>:/Gy>  # FunctionLevelLinking
        $<$<CONFIG:Release>:/Oi>  # IntrinsicFunctions
        $<$<CONFIG:Release>:/GL>  # WholeProgramOptimization
    )
    add_link_options(
        $<$<CONFIG:Release>:/LTCG>
        $<$<CONFIG:Debug>:/DEBUG:FULL>
    )
endif()

# ── GCC 兼容（MinGW-w64 cross-build）──
# clang-cl 在 CMake 里依然走 MSVC 分支，不会落到这里。
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
        -Wa,-mbig-obj           # 应对 PCH 与 ONNX 等大目标的段数限制
    )
    # 抑制 MinGW 头里几个高噪音的告警，方便 CI 日志阅读
    add_compile_options(
        -Wno-attributes
        -Wno-unknown-pragmas    # 源代码里有 #pragma comment(lib, ...)
    )
endif()

# ───────────────────────────────────────────────────────────────────
# 输出目录：所有 .exe/.dll/.lib 集中到 build/bin/<Config>/
# Multi-config 生成器（VS）会自动为每种 Config 维护独立子目录。
# 这样所有可执行文件天然能找到同目录下的 DLL，省去 PATH/拷贝烦恼。
# ───────────────────────────────────────────────────────────────────
set(MARDUK_OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${MARDUK_OUTPUT_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${MARDUK_OUTPUT_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${MARDUK_OUTPUT_DIR}")

foreach(_cfg IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${_cfg}" _cfg_up)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_cfg_up} "${MARDUK_OUTPUT_DIR}/${_cfg}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_cfg_up} "${MARDUK_OUTPUT_DIR}/${_cfg}")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_cfg_up} "${MARDUK_OUTPUT_DIR}/${_cfg}")
endforeach()

# vcpkg 在 Windows 下默认开启 applocal 部署，所有依赖 DLL 会自动拷到
# 可执行文件旁边，无需手动复制 vcpkg_installed\<triplet>\bin\*.dll。
# 跨编译时 (MinGW) applocal 不可用，但 vcpkg 会把 dll 装到
# vcpkg_installed/<triplet>/bin/，由 Dockerfile/CI 复制即可。
if(MSVC)
    set(VCPKG_APPLOCAL_DEPS ON CACHE BOOL "" FORCE)
    set(X_VCPKG_APPLOCAL_DEPS_INSTALL ON CACHE BOOL "" FORCE)
endif()

# ───────────────────────────────────────────────────────────────────
# 可选目标 —— 可单独关闭以适配跨编译（vcpkg 在 MinGW 下对 Qt6 /
# onnxruntime / opencv4 的支持仍不稳定）。
# ───────────────────────────────────────────────────────────────────
option(MARDUK_BUILD_GUI
    "Build the Qt6-based MardukGui front-end (requires qtbase + qttools)"
    ON)
option(MARDUK_BUILD_ZFW
    "Build ZfwInteractionDll and its consumers Marduk/TestApp \
(requires onnxruntime + opencv4 + cryptopp + gumbo)"
    ON)
option(MARDUK_BUILD_NETDIAG
    "Build NetworkDiagnosticDll \
(disabled by default on the linux-cross preset because Debian's \
mingw-w64 ships winhttp.h / wininet.h with a HTTP_VERSION_INFO typedef \
collision; works fine on MSVC and on llvm-mingw)"
    ON)

# 库（DLL）—— 三个轻量 DLL 一直构建
add_subdirectory(DNSManagerDll)
if(MARDUK_BUILD_NETDIAG)
    add_subdirectory(NetworkDiagnosticDll)
endif()
add_subdirectory(WifiPortalDll)

# 重型 DLL 与依赖它的 EXE
if(MARDUK_BUILD_ZFW)
    if(NOT MARDUK_BUILD_NETDIAG)
        message(FATAL_ERROR
            "MARDUK_BUILD_ZFW=ON requires MARDUK_BUILD_NETDIAG=ON \
(Marduk.exe links NetworkDiagnosticDll).")
    endif()
    add_subdirectory(ZfwInteractionDll)
    add_subdirectory(Marduk)
    add_subdirectory(TestApp)
endif()

# 提权代理（仅依赖 DNSManagerDll，跨编译也能跑）
add_subdirectory(MardukElevated)

# Qt GUI
if(MARDUK_BUILD_GUI)
    add_subdirectory(MardukGui)
endif()

# ───────────────────────────────────────────────────────────────────
# 摘要
# ───────────────────────────────────────────────────────────────────
message(STATUS "----- Marduk build configuration -----")
message(STATUS "  CMake version       : ${CMAKE_VERSION}")
message(STATUS "  Generator           : ${CMAKE_GENERATOR}")
message(STATUS "  Host                : ${CMAKE_HOST_SYSTEM_NAME}")
message(STATUS "  Target              : ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  Compiler            : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  C++ standard        : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Toolchain           : ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "  vcpkg triplet       : ${VCPKG_TARGET_TRIPLET}")
message(STATUS "  vcpkg overlays      : ${VCPKG_OVERLAY_TRIPLETS}")
message(STATUS "  Output directory    : ${MARDUK_OUTPUT_DIR}")
message(STATUS "  Build GUI           : ${MARDUK_BUILD_GUI}")
message(STATUS "  Build ZFW (heavy)   : ${MARDUK_BUILD_ZFW}")
message(STATUS "  Build NetDiag       : ${MARDUK_BUILD_NETDIAG}")
message(STATUS "--------------------------------------")
