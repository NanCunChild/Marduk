# NetworkDiagnosticDll —— 网络连通性/路由/DNS/TCP 诊断 + HTML 报告生成

set(NETDIAG_SOURCES
    NetworkDiagnostic.cpp
    NetworkDiagnostic.h
    HtmlTemplateManager.cpp
    HtmlTemplateManager.h
    DiagnosticHTMLTemplates.h
    SimpleTemplateProcessor.h
    ThreadPool.h
    dllmain.cpp
    framework.h
    pch.cpp
    pch.h
)

add_library(NetworkDiagnosticDll SHARED ${NETDIAG_SOURCES})

target_compile_definitions(NetworkDiagnosticDll PRIVATE
    NETWORKDIAGNOSTICDLL_EXPORTS
    _WINDOWS
    _USRDLL
)

target_precompile_headers(NetworkDiagnosticDll PRIVATE pch.h)

target_include_directories(NetworkDiagnosticDll
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Windows 网络栈：socket / IP helper / WinINet / WinHTTP / DNS API
target_link_libraries(NetworkDiagnosticDll PRIVATE
    ws2_32
    iphlpapi
    wininet
    winhttp
    dnsapi
)
