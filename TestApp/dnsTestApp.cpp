
#include <iostream>
#include <Windows.h>
#include "../DnsManagerDll/DnsManager.h"

void testDnsManager() {
    std::cout << "--- Testing DnsManagerDll: Full Service Lifecycle ---\n";

    // 1. 创建对象，自动检查并安装服务
    DNSManager dns_manager;
    if (!dns_manager.isReady()) {
        std::cout << "DnsManager failed to initialize. Exiting.\n";
        return;
    }

    // 2. 添加规则
    std::cout << "\nAttempting to add a rule...\n";
    if (dns_manager.addRule("127.0.0.1", "test.final.xidian")) {
        std::cout << "Rule added successfully.\n";
    }
    else {
        std::cout << "Failed to add rule.\n";
    }

    // 3. 启动服务 (或重启以应用规则)
    std::cout << "\nAttempting to start the service...\n";
    if (dns_manager.startService()) {
        std::cout << "Service started successfully.\n";
        std::cout << "You can now try 'ping test.final.xidian'.\n";
    }
    else {
        std::cout << "Failed to start service. Error code: " << GetLastError() << "\n";
    }

    system("pause");

    // 4. 卸载服务
    std::cout << "\nAttempting to uninstall the service...\n";
    if (dns_manager.uninstallService()) {
        std::cout << "Service uninstalled successfully.\n";
    }
    else {
        std::cout << "Failed to uninstall service. Error code: " << GetLastError() << "\n";
    }
}


int main() {
    SetConsoleOutputCP(CP_UTF8);
    testDnsManager();
    system("pause");
    return 0;
}