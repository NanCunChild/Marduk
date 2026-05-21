# MardukElevated —— 提权代理子进程
# 由 MardukGui 在需要管理员权限时调用 ShellExecute("runas", ...) 拉起。

add_executable(MardukElevated
    main.cpp
    MardukElevated.rc          # 嵌入 requireAdministrator manifest
)

target_link_libraries(MardukElevated PRIVATE
    DNSManagerDll
    shell32
)

# Console 子系统（默认）。wmain 入口在 MSVC 上由 _UNICODE 触发自动选择
# wmainCRTStartup；MinGW 需要 -municode（在根 CMakeLists 里统一处理）。
set_target_properties(MardukElevated PROPERTIES
    WIN32_EXECUTABLE FALSE
)
if(NOT MSVC)
    # wmain entry point requires -municode under MinGW; MSVC selects
    # wmainCRTStartup automatically when _UNICODE is defined.
    target_compile_options(MardukElevated PRIVATE -municode)
    target_link_options(MardukElevated    PRIVATE -municode)
endif()

# manifest 已经通过 .rc 内嵌，关掉 MSVC linker 的自动 manifest 生成，
# 否则两份 manifest 会被合并而引入意外的 asInvoker UAC 等级。
if(MSVC)
    target_link_options(MardukElevated PRIVATE /MANIFEST:NO)
endif()
