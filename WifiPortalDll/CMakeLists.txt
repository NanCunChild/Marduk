# WifiPortalDll —— 校园 Wi-Fi Portal 登录/状态查询封装
#
# 注意：本 DLL 的 pch.h 直接包含 <cpr/cpr.h> 与 <nlohmann/json.hpp>，
# 因此 PCH 编译需要在 link 第三方目标之后才有效（CMake 自动通过传递
# INTERFACE_INCLUDE_DIRECTORIES 解决）。

find_package(cpr CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set(WIFI_SOURCES
    WifiPortal.cpp
    WifiPortal.h
    dllmain.cpp
    framework.h
    pch.cpp
    pch.h
)

add_library(WifiPortalDll SHARED ${WIFI_SOURCES})

target_compile_definitions(WifiPortalDll PRIVATE
    WIFIPORTALDLL_EXPORTS
    _WINDOWS
    _USRDLL
)

target_include_directories(WifiPortalDll
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# 先链接（让 cpr / nlohmann_json 的 include dir 暴露给 PCH 编译）
target_link_libraries(WifiPortalDll PRIVATE
    cpr::cpr
    nlohmann_json::nlohmann_json
)

# 再启用 PCH —— pch.h 内的 <cpr/cpr.h> / <nlohmann/json.hpp> 此时可被解析
target_precompile_headers(WifiPortalDll PRIVATE pch.h)
