# MardukGui —— Qt6 图形界面前端

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Concurrent)

set(SOURCES
    main.cpp
    MainWindow.cpp
    MainWindow.h
    pages/LoginPage.cpp
    pages/LoginPage.h
    pages/DnsManagerPage.cpp
    pages/DnsManagerPage.h
    pages/DiagnosticsPage.cpp
    pages/DiagnosticsPage.h
    pages/WifiPortalPage.cpp
    pages/WifiPortalPage.h
    utils/ElevationHelper.cpp
    utils/ElevationHelper.h
    utils/AsyncWorker.h
    resources/resources.qrc
)

qt_add_executable(MardukGui WIN32 ${SOURCES})

target_include_directories(MardukGui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(MardukGui PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Concurrent
    # 仓库内的 4 个 DLL —— 直接依赖 CMake target，include 路径与
    # import lib 自动通过 PUBLIC 接口传播。
    DNSManagerDll
    NetworkDiagnosticDll
    WifiPortalDll
    ZfwInteractionDll
    # Windows 系统库
    shell32
    ole32
)

set_target_properties(MardukGui PROPERTIES
    WIN32_EXECUTABLE TRUE       # /SUBSYSTEM:WINDOWS
    VS_DPI_AWARE "PerMonitor"
)
