# TestApp —— 单元/手测可执行（当前只构建 TestApp.cpp，
# dnsTestApp.cpp / zfwTestApp.cpp 是仓库里两个孤儿测试程序，
# 与原 .vcxproj 行为保持一致：留在磁盘但不编入构建目标）。

add_executable(TestApp TestApp.cpp)

target_link_libraries(TestApp PRIVATE
    DNSManagerDll
    ZfwInteractionDll
    shell32
)

set_target_properties(TestApp PROPERTIES
    WIN32_EXECUTABLE FALSE   # Console (wmain)
)
if(NOT MSVC)
    target_compile_options(TestApp PRIVATE -municode)
    target_link_options(TestApp    PRIVATE -municode)
endif()
