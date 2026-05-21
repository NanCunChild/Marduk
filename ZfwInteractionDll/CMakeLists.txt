# ZfwInteractionDll —— 西电 zfw 平台登录 + CRNN 验证码识别
#
# 这是依赖最重的 DLL：cpr / gumbo / nlohmann-json / cryptopp /
# onnxruntime / opencv4。其中 onnxruntime 必须经由 custom-x64-windows
# triplet 构建（custom-triplets/custom-x64-windows.cmake 强制注入
# -DONNX_DISABLE_STATIC_REGISTRATION=ON），否则模型加载会因算子
# schema 重复注册而被判定为 invalid model。

find_package(cpr CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(cryptopp CONFIG REQUIRED)
find_package(onnxruntime CONFIG REQUIRED)
find_package(OpenCV CONFIG REQUIRED)
# vcpkg 的 gumbo port 提供 unofficial 命名空间下的 config
find_package(unofficial-gumbo CONFIG REQUIRED)

set(ZFW_SOURCES
    ZfwManager.cpp
    ZfwManager.h
    GumboWrapper.h
    dllmain.cpp
    framework.h
    pch.cpp
    pch.h
    resource.h
    ZfwInteractionDll.rc      # MSVC RC 编译器自动处理
)

add_library(ZfwInteractionDll SHARED ${ZFW_SOURCES})

target_compile_definitions(ZfwInteractionDll PRIVATE
    ZFWINTERACTIONDLL_EXPORTS
    _WINDOWS
    _USRDLL
)

target_include_directories(ZfwInteractionDll
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(ZfwInteractionDll PRIVATE
    cpr::cpr
    nlohmann_json::nlohmann_json
    cryptopp::cryptopp
    onnxruntime::onnxruntime
    ${OpenCV_LIBS}
    unofficial::gumbo::gumbo
)

target_precompile_headers(ZfwInteractionDll PRIVATE pch.h)
