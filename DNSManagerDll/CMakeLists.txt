# DNSManagerDll —— 本地 DNS 代理（Acrylic）服务管理 DLL
#
# 目标名必须是 DNSManagerDll，CMake 会据此自动定义 DNSManagerDll_EXPORTS，
# 与 DNSManager.h 中 __declspec(dllexport/dllimport) 的判定宏一致。

set(DNS_SOURCES
    DNSManager.cpp
    DNSManager.h
    dllmain.cpp
    framework.h
    pch.cpp
    pch.h
)

add_library(DNSManagerDll SHARED ${DNS_SOURCES})

# 与原 vcxproj 中 DNSMANAGERDLL_EXPORTS 等价；CMake 会自动给 SHARED
# 目标定义 <TargetName>_EXPORTS，但原代码用的是大写宏，保留兼容。
target_compile_definitions(DNSManagerDll PRIVATE
    DNSMANAGERDLL_EXPORTS
    _WINDOWS
    _USRDLL
)

# 预编译头：CMake 会接管 /Yc /Yu /Fp，pch.cpp 退化为普通源文件。
target_precompile_headers(DNSManagerDll PRIVATE pch.h)

# 公共头给消费者使用（Marduk、MardukGui、MardukElevated、TestApp）。
target_include_directories(DNSManagerDll
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Windows 服务管理 API
target_link_libraries(DNSManagerDll PRIVATE advapi32)

# Acrylic 部署文件 —— 原 vcxproj 中通过 CopyFileToFolders + DeploymentContent
# 实现，迁移到 CMake 的 POST_BUILD 拷贝。所有 EXE 与 DLL 都输出到同一个
# 目录，故拷到 DLL 旁即可。
set(ACRYLIC_FILES
    AcrylicFiles/AcrylicCache.dat
    AcrylicFiles/AcrylicConfiguration.ini
    AcrylicFiles/AcrylicConsole.exe
    AcrylicFiles/AcrylicService.exe
    AcrylicFiles/AcrylicHosts.txt
)

foreach(_f IN LISTS ACRYLIC_FILES)
    add_custom_command(TARGET DNSManagerDll POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/${_f}"
            "$<TARGET_FILE_DIR:DNSManagerDll>"
        COMMENT "Deploying ${_f}"
        VERBATIM
    )
endforeach()
