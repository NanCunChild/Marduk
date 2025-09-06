#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <locale>
#include <Windows.h>
#include <filesystem>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <io.h>
#include <fcntl.h>
#include <iomanip>
#include <chrono>

#pragma comment(lib, "NetworkDiagnosticDll.lib")

#include "../ZfwInteractionDll/ZfwManager.h"
#include "../DNSManagerDll/DNSManager.h"
#include "../NetworkDiagnosticDll/NetworkDiagnostic.h"

#pragma comment(lib, "shell32.lib")


std::unique_ptr<ZfwManager> g_zfwManager;
std::unique_ptr<DNSManager> g_dnsManager;
std::unique_ptr<NetworkDiagnostic> g_networkDiagnostic;
LoginResult g_loginResult;

bool isPrivilegedOperation(const std::wstring& command) {
    return (command == L"dnsdep" || command == L"dnsadd" ||
        command == L"dnsrm" || command == L"dnsclear" ||
        command == L"pasopt");
}

// --- 编码转换辅助函数 ---
// 将 UTF-8 (std::string) 转换为 UTF-16 (std::wstring)
std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// 将 UTF-16 (std::wstring) 转换为 UTF-8 (std::string)
std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}


// --- 函数声明 ---
bool IsRunningAsAdmin();
bool requestElevation();
bool hasAdminPrivilegesForOperation();
void printHelp();
void handleLogin();
void handleZfwInfo();
void handleDnsDeploy();
void handleDnsAdd();
void handleDnsRemove();
void handleDnsList();
void handleDnsClear();
void handlePasopt();
void handleDiagnose();
std::wstring get_executable_dir();
void initializeManagers();

// 错误码转换函数
std::wstring dnsErrorCodeToWString(DnsErrorCode code) {
    switch (code) {
    case DnsErrorCode::SUCCESS: return L"SUCCESS";
    case DnsErrorCode::PERMISSION_DENIED: return L"PERMISSION_DENIED";
    case DnsErrorCode::PERMISSION_ADMIN_REQUIRED: return L"PERMISSION_ADMIN_REQUIRED";
    case DnsErrorCode::SERVICE_NOT_FOUND: return L"SERVICE_NOT_FOUND";
    case DnsErrorCode::SERVICE_INSTALL_FAILED: return L"SERVICE_INSTALL_FAILED";
    case DnsErrorCode::SERVICE_UNINSTALL_FAILED: return L"SERVICE_UNINSTALL_FAILED";
    case DnsErrorCode::SERVICE_START_FAILED: return L"SERVICE_START_FAILED";
    case DnsErrorCode::SERVICE_STOP_FAILED: return L"SERVICE_STOP_FAILED";
    case DnsErrorCode::SERVICE_ALREADY_RUNNING: return L"SERVICE_ALREADY_RUNNING";
    case DnsErrorCode::SERVICE_ALREADY_STOPPED: return L"SERVICE_ALREADY_STOPPED";
    case DnsErrorCode::FILE_NOT_FOUND: return L"FILE_NOT_FOUND";
    case DnsErrorCode::FILE_ACCESS_DENIED: return L"FILE_ACCESS_DENIED";
    case DnsErrorCode::FILE_WRITE_FAILED: return L"FILE_WRITE_FAILED";
    case DnsErrorCode::FILE_READ_FAILED: return L"FILE_READ_FAILED";
    case DnsErrorCode::CONFIG_INVALID_IP: return L"CONFIG_INVALID_IP";
    case DnsErrorCode::CONFIG_INVALID_HOSTNAME: return L"CONFIG_INVALID_HOSTNAME";
    case DnsErrorCode::CONFIG_RULE_EXISTS: return L"CONFIG_RULE_EXISTS";
    case DnsErrorCode::SYSTEM_SCM_ACCESS_FAILED: return L"SYSTEM_SCM_ACCESS_FAILED";
    case DnsErrorCode::SYSTEM_SERVICE_HANDLE_FAILED: return L"SYSTEM_SERVICE_HANDLE_FAILED";
    case DnsErrorCode::SYSTEM_UNKNOWN_ERROR: return L"SYSTEM_UNKNOWN_ERROR";
    default: return L"UNKNOWN_ERROR_CODE";
    }
}

std::wstring diagnosticErrorCodeToWString(DiagnosticErrorCode code) {
    switch (code) {
    case DiagnosticErrorCode::SUCCESS: return L"SUCCESS";
    case DiagnosticErrorCode::FILE_CREATE_FAILED: return L"FILE_CREATE_FAILED";
    case DiagnosticErrorCode::FILE_WRITE_FAILED: return L"FILE_WRITE_FAILED";
    case DiagnosticErrorCode::FILE_PATH_INVALID: return L"FILE_PATH_INVALID";
    case DiagnosticErrorCode::SYSTEM_WMI_ACCESS_FAILED: return L"SYSTEM_WMI_ACCESS_FAILED";
    case DiagnosticErrorCode::SYSTEM_REGISTRY_ACCESS_FAILED: return L"SYSTEM_REGISTRY_ACCESS_FAILED";
    case DiagnosticErrorCode::SYSTEM_NETWORK_INFO_FAILED: return L"SYSTEM_NETWORK_INFO_FAILED";
    case DiagnosticErrorCode::SYSTEM_PERMISSION_DENIED: return L"SYSTEM_PERMISSION_DENIED";
    case DiagnosticErrorCode::NETWORK_PING_FAILED: return L"NETWORK_PING_FAILED";
    case DiagnosticErrorCode::NETWORK_DNS_QUERY_FAILED: return L"NETWORK_DNS_QUERY_FAILED";
    case DiagnosticErrorCode::NETWORK_CONNECTION_FAILED: return L"NETWORK_CONNECTION_FAILED";
    case DiagnosticErrorCode::NETWORK_TIMEOUT: return L"NETWORK_TIMEOUT";
    case DiagnosticErrorCode::CONFIG_INVALID_TARGET: return L"CONFIG_INVALID_TARGET";
    case DiagnosticErrorCode::CONFIG_INVALID_PATH: return L"CONFIG_INVALID_PATH";
    case DiagnosticErrorCode::SYSTEM_UNKNOWN_ERROR: return L"SYSTEM_UNKNOWN_ERROR";
    default: return L"UNKNOWN_ERROR_CODE";
    }
}

// 请求管理员权限
bool requestElevation() {
    std::wcout << L"\n⚠️  此操作需要管理员权限！" << std::endl;
    std::wcout << L"是否要以管理员身份重新启动程序? (y/n): ";

    std::wstring choice;
    std::getline(std::wcin, choice);

    if (choice == L"y" || choice == L"Y" || choice == L"是") {
        // 获取当前程序路径
        wchar_t szPath[MAX_PATH];
        GetModuleFileName(NULL, szPath, MAX_PATH);

        // 以管理员权限重新启动
        SHELLEXECUTEINFO sei = { 0 };
        sei.cbSize = sizeof(sei);
        sei.lpVerb = L"runas";  // 请求管理员权限
        sei.lpFile = szPath;
        sei.nShow = SW_SHOWNORMAL;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteEx(&sei)) {
            std::wcout << L"正在以管理员权限重新启动..." << std::endl;

            if (sei.hProcess) {
                WaitForSingleObject(sei.hProcess, 3000);
                CloseHandle(sei.hProcess);
            }

            return true;
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_CANCELLED) {
                std::wcout << L"用户取消了权限提升请求。" << std::endl;
            }
            else {
                std::wcout << L"权限提升失败，错误代码: " << error << std::endl;
            }
            return false;
        }
    }

    std::wcout << L"操作已取消。" << std::endl;
    return false;
}

// 检查当前是否有管理员权限（用于特定操作）
bool hasAdminPrivilegesForOperation() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsGroup = NULL;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &administratorsGroup)) {
        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(administratorsGroup);
    }

    return isAdmin == TRUE;
}


// 使用 wmain 作为宽字符入口点
int wmain(int argc, wchar_t* argv[]) {
    // 1. 设置控制台为 UTF-16 模式，完美支持 wcout
    int result = _setmode(_fileno(stdout), _O_U16TEXT);
    if (result == -1) {
        std::wcout << L"警告: 无法设置控制台为UTF-16模式\n";
    }

    std::wcout << L"--- 西电校园网辅助工具 (CLI v1.0) ---" << std::endl;
    std::wcout << L"欢迎使用！输入 'help' 查看所有可用命令。" << std::endl;

    // 显示当前权限状态
    if (IsRunningAsAdmin()) {
        std::wcout << L"🔐 当前运行模式: 管理员权限" << std::endl;
    }
    else {
        std::wcout << L"😅 当前运行模式: 普通用户权限" << std::endl;
        std::wcout << L"💡 提示: 某些功能需要管理员权限时会自动提示" << std::endl;
    }

    initializeManagers(); // 初始化全局管理器

    std::wstring command;
    while (true) {
        std::wcout << L"\n> ";
        std::getline(std::wcin, command);

        if (isPrivilegedOperation(command) && !IsRunningAsAdmin()) {
            if (requestElevation()) {
                return 0;
            }
            else {
                continue;
            }
        }

        if (command == L"help") printHelp();
        else if (command == L"login") handleLogin();
        else if (command == L"zfwinfo") handleZfwInfo();
        else if (command == L"dnsdep") handleDnsDeploy();
        else if (command == L"dnsadd") handleDnsAdd();
        else if (command == L"dnsrm") handleDnsRemove();
        else if (command == L"dnslist") handleDnsList();
        else if (command == L"dnsclear") handleDnsClear();
        else if (command == L"pasopt") handlePasopt();
        else if (command == L"diagno") handleDiagnose();
        else if (command == L"exit" || command == L"quit") break;
        else if (command.empty()) {}
        else {
            std::wcout << L"未知命令。输入 'help' 查看命令列表。" << std::endl;
        }
    }
    return 0;
}

void printHelp() {
    std::wcout << L"可用命令:\n";
    std::wcout << L"=== 无需权限的命令 ===\n";
    std::wcout << L"  login       - 登录 zfw.xidian.edu.cn 平台\n";
    std::wcout << L"  zfwinfo     - (需先登录) 显示当前登录用户的详细信息\n";
    std::wcout << L"  diagno      - 🔍 生成详细的网络诊断报告\n";
    std::wcout << L"  dnslist     - 列出所有当前DNS规则\n";
    std::wcout << L"  help        - 显示此帮助信息\n";
    std::wcout << L"  exit        - 退出程序\n\n";

    std::wcout << L"=== 需要管理员权限的命令 ===\n";
    if (!IsRunningAsAdmin()) {
        std::wcout << L"  (以下命令执行时会自动请求权限提升)\n";
    }
    std::wcout << L"  dnsdep      - 🔧 部署本地DNS代理服务\n";
    std::wcout << L"  dnsadd      - ➕ 添加一条自定义DNS规则\n";
    std::wcout << L"  dnsrm       - ➖ 删除一条DNS规则\n";
    std::wcout << L"  dnsclear    - 🗑️ 清空所有DNS规则\n";
    std::wcout << L"  pasopt      - ⚡ 一键优化网络设置\n";
}

void handleLogin() {
    if (!g_zfwManager) {
        std::wcout << L"ZfwManager 初始化失败，请检查模型文件是否存在。" << std::endl;
        return;
    }

    std::wcout << L"--- 统一认证平台登录 ---\n";
    std::wstring w_username, w_password;
    std::wcout << L"请输入学号: ";
    std::getline(std::wcin, w_username);
    std::wcout << L"请输入密码: ";
    std::getline(std::wcin, w_password);

    if (w_username.empty() || w_password.empty()) {
        std::wcout << L"学号或密码不能为空。" << std::endl;
        return;
    }

    std::wcout << L"正在登录...\n";
    try {
        // 在调用 DLL 前，将 wstring(UTF-16) 转换为 string(UTF-8)
        std::string u8_username = wstring_to_utf8(w_username);
        std::string u8_password = wstring_to_utf8(w_password);

        g_loginResult = g_zfwManager->login(u8_username, u8_password);

        std::wcout << L"\n--- 登录结果 ---\n";
        if (g_loginResult.isSuccess()) {
            std::wcout << L"状态: 成功\n";
            std::wcout << L"消息: " << utf8_to_wstring(g_loginResult.error_message) << L"\n";
            std::wcout << L"登录成功！现在可以使用 'zfwinfo' 命令查看详细信息。" << std::endl;
        }
        else {
            std::wcout << L"状态: 失败\n";
            std::wcout << L"错误码: " << static_cast<int>(g_loginResult.error_code) << L"\n";
            std::wcout << L"错误信息: " << utf8_to_wstring(g_loginResult.error_message) << L"\n";
        }
    }
    catch (const std::exception& e) {
        std::wcout << L"登录过程中发生异常: " << utf8_to_wstring(e.what()) << std::endl;
    }
    catch (...) {
        std::wcout << L"登录过程中发生未知异常。" << std::endl;
    }
}

void handleZfwInfo() {
    if (!g_loginResult.isSuccess()) {
        std::wcout << L"请先使用 'login' 命令成功登录。" << std::endl;
        return;
    }

    const UserInfo& userInfo = g_loginResult.user_info;
    std::wcout << L"\n--- 已登录用户信息 ---\n";
    std::wcout << L"--- 用户面板 ---\n";
    std::wcout << L"学号: " << utf8_to_wstring(userInfo.username) << L"\n";
    std::wcout << L"姓名: " << utf8_to_wstring(userInfo.realname) << L"\n";
    std::wcout << L"账户状态: " << utf8_to_wstring(userInfo.user_status) << L"\n";
    std::wcout << L"电子钱包: " << userInfo.wallet << L" 元\n";

    std::wcout << L"\n--- 套餐面板 ---\n";
    std::wcout << L"套餐总数: " << userInfo.plan_num << L"\n";
    std::wcout << L"是否包含电信套餐: " << (userInfo.telecom_plan ? L"是" : L"否") << L"\n";
    std::wcout << L"是否包含联通套餐: " << (userInfo.unicom_plan ? L"是" : L"否") << L"\n";
    std::wcout << L"是否包含移动套餐: " << (userInfo.mobile_plan ? L"是" : L"否") << L"\n";

    std::wcout << L"\n--- IP 面板 ---\n";
    std::wcout << L"免费IP数量: " << userInfo.ip_free_count << L"\n";
    for (const auto& ip : userInfo.ip_free_list) {
        std::wcout << L"  - " << utf8_to_wstring(ip) << L"\n";
    }
    std::wcout << L"付费IP数量: " << userInfo.ip_pay_count << L"\n";
    for (const auto& ip : userInfo.ip_pay_list) {
        std::wcout << L"  - " << utf8_to_wstring(ip) << L"\n";
    }
}

void handleDnsDeploy() {
    if (!g_dnsManager) {
        std::wcout << L"DNS Manager 未初始化。" << std::endl;
        return;
    }

    std::wcout << L"--- DNS 服务部署 ---\n";

    // 初始化DNS管理器
    DnsResult init_result = g_dnsManager->initialize();
    if (!init_result.isSuccess()) {
        std::wcout << L"DNS Manager 初始化失败: "
            << utf8_to_wstring(init_result.error_message) << std::endl;
        return;
    }

    // 获取服务状态
    DnsServiceInfo info = g_dnsManager->getServiceInfo();
    std::wcout << L"当前服务状态:\n";
    std::wcout << L"  已安装: " << (info.is_installed ? L"是" : L"否") << L"\n";
    std::wcout << L"  正在运行: " << (info.is_running ? L"是" : L"否") << L"\n";
    std::wcout << L"  规则数量: " << info.rule_count << L"\n";
    std::wcout << L"  服务路径: " << utf8_to_wstring(info.service_path) << L"\n";

    // 安装服务（如果需要）
    if (!info.is_installed) {
        std::wcout << L"\n正在安装 DNS 服务...\n";
        DnsResult install_result = g_dnsManager->installService();
        if (!install_result.isSuccess()) {
            std::wcout << L"安装失败 (" << static_cast<int>(install_result.error_code)
                << L"): " << utf8_to_wstring(install_result.error_message) << std::endl;
            return;
        }
        std::wcout << L"✓ 服务安装成功!\n";
    }
    else {
        std::wcout << L"✓ 服务已安装。\n";
    }

    // 启动服务（如果需要）
    info = g_dnsManager->getServiceInfo(); // 更新状态
    if (!info.is_running) {
        std::wcout << L"正在启动 DNS 服务...\n";
        DnsResult start_result = g_dnsManager->startService();
        if (start_result.isSuccess()) {
            std::wcout << L"✓ DNS 服务启动成功!\n";
        }
        else {
            std::wcout << L"启动失败 (" << static_cast<int>(start_result.error_code)
                << L"): " << utf8_to_wstring(start_result.error_message) << std::endl;
        }
    }
    else {
        std::wcout << L"✓ DNS 服务已在运行。\n";
    }

    std::wcout << L"\nDNS 服务部署完成！" << std::endl;
}

void handleDnsAdd() {
    if (!g_dnsManager) {
        std::wcout << L"DNS Manager 未初始化。" << std::endl;
        return;
    }

    std::wcout << L"--- 添加 DNS 规则 ---\n";

    std::wstring w_ip, w_hostname;
    std::wcout << L"请输入 IP 地址: ";
    std::getline(std::wcin, w_ip);
    std::wcout << L"请输入主机名: ";
    std::getline(std::wcin, w_hostname);

    if (w_ip.empty() || w_hostname.empty()) {
        std::wcout << L"IP 地址和主机名不能为空。" << std::endl;
        return;
    }

    std::string ip = wstring_to_utf8(w_ip);
    std::string hostname = wstring_to_utf8(w_hostname);

    std::wcout << L"正在添加规则: " << w_ip << L" -> " << w_hostname << L"\n";

    DnsResult result = g_dnsManager->addRule(ip, hostname);
    if (result.isSuccess()) {
        std::wcout << L"✓ 规则添加成功: " << utf8_to_wstring(result.error_message) << std::endl;

        // 询问是否重启DNS服务以应用更改
        std::wcout << L"是否重启DNS服务以应用更改？(y/N): ";
        std::wstring response;
        std::getline(std::wcin, response);
        if (response == L"y" || response == L"Y") {
            DnsResult restart_result = g_dnsManager->restartService();
            if (restart_result.isSuccess()) {
                std::wcout << L"✓ DNS 服务重启成功，规则已生效。" << std::endl;
            }
            else {
                std::wcout << L"⚠ DNS 服务重启失败: " << utf8_to_wstring(restart_result.error_message) << std::endl;
            }
        }
    }
    else {
        std::wcout << L"✗ 规则添加失败 (" << static_cast<int>(result.error_code)
            << L"): " << utf8_to_wstring(result.error_message) << std::endl;
    }
}

void handleDnsRemove() {
    if (!g_dnsManager) {
        std::wcout << L"DNS Manager 未初始化。" << std::endl;
        return;
    }

    std::wcout << L"--- 删除 DNS 规则 ---\n";

    std::wstring w_hostname;
    std::wcout << L"请输入要删除的主机名: ";
    std::getline(std::wcin, w_hostname);

    if (w_hostname.empty()) {
        std::wcout << L"主机名不能为空。" << std::endl;
        return;
    }

    std::string hostname = wstring_to_utf8(w_hostname);
    std::wcout << L"正在删除规则: " << w_hostname << L"\n";

    DnsResult result = g_dnsManager->removeRule(hostname);
    if (result.isSuccess()) {
        std::wcout << L"✓ 规则删除成功: " << utf8_to_wstring(result.error_message) << std::endl;

        // 询问是否重启DNS服务以应用更改
        std::wcout << L"是否重启DNS服务以应用更改？(y/N): ";
        std::wstring response;
        std::getline(std::wcin, response);
        if (response == L"y" || response == L"Y") {
            DnsResult restart_result = g_dnsManager->restartService();
            if (restart_result.isSuccess()) {
                std::wcout << L"✓ DNS 服务重启成功，更改已生效。" << std::endl;
            }
            else {
                std::wcout << L"⚠ DNS 服务重启失败: " << utf8_to_wstring(restart_result.error_message) << std::endl;
            }
        }
    }
    else {
        std::wcout << L"✗ 规则删除失败 (" << static_cast<int>(result.error_code)
            << L"): " << utf8_to_wstring(result.error_message) << std::endl;
    }
}

void handleDnsList() {
    if (!g_dnsManager) {
        std::wcout << L"DNS Manager 未初始化。" << std::endl;
        return;
    }

    std::wcout << L"--- DNS 规则列表 ---\n";

    std::vector<std::pair<std::string, std::string>> rules;
    DnsResult result = g_dnsManager->listRules(rules);

    if (!result.isSuccess()) {
        std::wcout << L"✗ 获取规则列表失败 (" << static_cast<int>(result.error_code)
            << L"): " << utf8_to_wstring(result.error_message) << std::endl;
        return;
    }

    if (rules.empty()) {
        std::wcout << L"当前没有DNS规则。" << std::endl;
        return;
    }

    std::wcout << L"当前DNS规则 (共 " << rules.size() << L" 条):\n";
    std::wcout << L"┌─────────────────┬────────────────────────────────────┐\n";
    std::wcout << L"│   IP 地址       │            主机名                  │\n";
    std::wcout << L"├─────────────────┼────────────────────────────────────┤\n";

    for (const auto& rule : rules) {
        std::wstring ip = utf8_to_wstring(rule.first);
        std::wstring hostname = utf8_to_wstring(rule.second);
        std::wcout << L"│ " << std::left << std::setw(15) << ip
            << L" │ " << std::setw(34) << hostname << L" │\n";
    }
    std::wcout << L"└─────────────────┴────────────────────────────────────┘\n";
}

void handleDnsClear() {
    if (!g_dnsManager) {
        std::wcout << L"DNS Manager 未初始化。" << std::endl;
        return;
    }

    std::wcout << L"--- 清空所有 DNS 规则 ---\n";
    std::wcout << L"⚠ 警告: 此操作将删除所有DNS规则，且无法撤销！\n";
    std::wcout << L"确定要继续吗？请输入 'YES' 确认: ";

    std::wstring confirmation;
    std::getline(std::wcin, confirmation);

    if (confirmation != L"YES") {
        std::wcout << L"操作已取消。" << std::endl;
        return;
    }

    std::wcout << L"正在清空所有DNS规则...\n";

    DnsResult result = g_dnsManager->clearAllRules();
    if (result.isSuccess()) {
        std::wcout << L"✓ 所有DNS规则已清空: " << utf8_to_wstring(result.error_message) << std::endl;

        // 询问是否重启DNS服务以应用更改
        std::wcout << L"是否重启DNS服务以应用更改？(y/N): ";
        std::wstring response;
        std::getline(std::wcin, response);
        if (response == L"y" || response == L"Y") {
            DnsResult restart_result = g_dnsManager->restartService();
            if (restart_result.isSuccess()) {
                std::wcout << L"✓ DNS 服务重启成功，更改已生效。" << std::endl;
            }
            else {
                std::wcout << L"⚠ DNS 服务重启失败: " << utf8_to_wstring(restart_result.error_message) << std::endl;
            }
        }
    }
    else {
        std::wcout << L"✗ 清空规则失败 (" << static_cast<int>(result.error_code)
            << L"): " << utf8_to_wstring(result.error_message) << std::endl;
    }
}

void handlePasopt() {
    std::wcout << L"--- 一键网络优化 ---\n";
    std::wcout << L"正在执行以下优化操作:\n";
    std::wcout << L"1. 部署DNS代理服务\n";
    std::wcout << L"2. 添加常用域名IPv6屏蔽规则\n";
    std::wcout << L"3. 优化DNS查询设置\n\n";

    // 1. 部署DNS服务
    std::wcout << L"[1/3] 部署DNS代理服务...\n";
    handleDnsDeploy();

    // 2. 添加常用的IPv6屏蔽规则
    std::wcout << L"\n[2/3] 添加IPv6屏蔽规则...\n";
    if (g_dnsManager) {
        std::vector<std::pair<std::string, std::string>> ipv6_rules = {
            {"127.0.0.1", "www.youtube.com"}, // 这些在中国加和不加无所谓
            {"127.0.0.1", "youtube.com"},
            {"127.0.0.1", "www.bilibili.com"},
            {"127.0.0.1", "bilibili.com"},
            {"127.0.0.1", "www.netflix.com"},
            {"127.0.0.1", "netflix.com"},
            {"127.0.0.1", "www.youku.com"},
            {"127.0.0.1", "youku.com"},
            {"127.0.0.1", "www.netflix.com"},
            {"127.0.0.1", "netflix.com"},
            {"127.0.0.1", "v.qq.com"},
            {"127.0.0.1", "iqiyi.com"},
            {"127.0.0.1", "douyin.com"}
        };

        int success_count = 0;
        for (const auto& rule : ipv6_rules) {
            DnsResult result = g_dnsManager->addRule(rule.first, rule.second);
            if (result.isSuccess()) {
                success_count++;
                std::wcout << L"✓ 已添加: " << utf8_to_wstring(rule.second) << L"\n";
            }
            else if (result.error_code == DnsErrorCode::CONFIG_RULE_EXISTS) {
                success_count++;
                std::wcout << L"- 已存在: " << utf8_to_wstring(rule.second) << L"\n";
            }
            else {
                std::wcout << L"✗ 失败: " << utf8_to_wstring(rule.second) << L" - "
                    << utf8_to_wstring(result.error_message) << L"\n";
            }
        }
        std::wcout << L"IPv6屏蔽规则添加完成 (" << success_count << L"/" << ipv6_rules.size() << L")\n";
    }

    // 3. 重启DNS服务应用更改
    std::wcout << L"\n[3/3] 重启DNS服务应用更改...\n";
    if (g_dnsManager) {
        DnsResult restart_result = g_dnsManager->restartService();
        if (restart_result.isSuccess()) {
            std::wcout << L"✓ DNS 服务重启成功，所有优化已生效。\n";
        }
        else {
            std::wcout << L"⚠ DNS 服务重启失败: " << utf8_to_wstring(restart_result.error_message) << L"\n";
        }
    }

    std::wcout << L"\n🎉 网络优化完成！\n";
    std::wcout << L"建议在浏览器中清除DNS缓存或重启浏览器以获得最佳效果。\n";
}

// 辅助函数：显示诊断结果摘要
void displayDiagnosticSummary(const DiagnosticResult& result) {
    std::wcout << L"\n=== 诊断结果摘要 ===" << std::endl;

    // 网络接口状态
    int active_interfaces = 0;
    for (const auto& iface : result.network_interfaces) {
        if (iface.is_enabled && iface.ip_address != "0.0.0.0") {
            active_interfaces++;
        }
    }
    std::wcout << L"活跃网络接口: " << active_interfaces << L"/" << result.network_interfaces.size() << std::endl;

    // Ping测试结果
    int successful_pings = 0;
    for (const auto& ping : result.ping_results) {
        if (ping.success) successful_pings++;
    }
    std::wcout << L"Ping测试成功: " << successful_pings << L"/" << result.ping_results.size();
    if (successful_pings < result.ping_results.size()) {
        std::wcout << L" ⚠️";
    }
    else {
        std::wcout << L" ✅";
    }
    std::wcout << std::endl;

    // DNS测试结果
    int successful_dns = 0;
    for (const auto& dns : result.dns_results) {
        if (dns.success) successful_dns++;
    }
    std::wcout << L"DNS解析成功: " << successful_dns << L"/" << result.dns_results.size();
    if (successful_dns < result.dns_results.size()) {
        std::wcout << L" ⚠️";
    }
    else {
        std::wcout << L" ✅";
    }
    std::wcout << std::endl;

    // TCP连接测试结果
    int successful_tcp = 0;
    for (const auto& tcp : result.tcp_results) {
        if (tcp.success) successful_tcp++;
    }
    std::wcout << L"TCP连接成功: " << successful_tcp << L"/" << result.tcp_results.size();
    if (successful_tcp < result.tcp_results.size()) {
        std::wcout << L" ⚠️";
    }
    else {
        std::wcout << L" ✅";
    }
    std::wcout << std::endl;

    // 代理状态
    std::wcout << L"代理配置: " << (result.proxy_config.proxy_enabled ? L"已启用 🔄" : L"未启用 ➖") << std::endl;

    // 如果有问题，提供简单建议
    if (successful_pings == 0) {
        std::wcout << L"\n⚠️  网络连接问题：所有Ping测试都失败了，请检查网络连接。" << std::endl;
    }
    if (successful_dns < result.dns_results.size() / 2) {
        std::wcout << L"\n⚠️  DNS解析问题：建议检查DNS服务器设置。" << std::endl;
    }
}

void handleDiagnose() {
    if (!g_networkDiagnostic) {
        std::wcout << L"网络诊断模块未初始化。" << std::endl;
        return;
    }

    std::wcout << L"=== 网络诊断工具 ===" << std::endl;
    std::wcout << L"正在执行全面网络诊断，这可能需要几分钟时间..." << std::endl;
    std::wcout << L"请稍候..." << std::endl;

    std::wcout << L"\n[1/4] 正在收集系统信息..." << std::endl;

    DiagnosticConfig config;
    config.ping_targets = {
        "8.8.8.8", "10.255.44.33", "223.5.5.5",
        "baidu.com", "w.xidian.edu.cn", "github.com"
    };
    config.dns_test_domains = {
        "baidu.com", "w.xidian.edu.cn", "github.com", "google.com"
    };
    config.tcp_test_targets = {
        {"baidu.com", 80}, {"baidu.com", 443},
        {"www.xidian.edu.cn", 80}, {"www.xidian.edu.cn", 443},
        {"github.com", 80}, {"github.com", 443}
    };

    std::wcout << L"[2/4] 正在执行网络连通性测试..." << std::endl;
    std::wcout << L"[3/4] 正在执行DNS解析测试..." << std::endl;
    std::wcout << L"[4/4] 正在执行TCP连接测试..." << std::endl;

    // 执行完整诊断
    DiagnosticResult result = g_networkDiagnostic->runFullDiagnostic(config);

    if (!result.isSuccess()) {
        std::wcout << L"诊断执行失败!" << std::endl;
        std::wcout << L"错误码: " << static_cast<int>(result.error_code)
            << L" (" << diagnosticErrorCodeToWString(result.error_code) << L")" << std::endl;
        std::wcout << L"错误信息: " << utf8_to_wstring(result.error_message) << std::endl;
        return;
    }

    std::wcout << L"\n✅ 网络诊断完成!" << std::endl;

    // 显示简要统计信息
    std::wcout << L"\n=== 诊断统计 ===" << std::endl;
    std::wcout << L"检测到网络接口: " << result.network_interfaces.size() << L" 个" << std::endl;
    std::wcout << L"路由表条目: " << result.routing_table.size() << L" 条" << std::endl;
    std::wcout << L"Ping测试: " << result.ping_results.size() << L" 个目标" << std::endl;
    std::wcout << L"DNS测试: " << result.dns_results.size() << L" 个域名" << std::endl;
    std::wcout << L"TCP连接测试: " << result.tcp_results.size() << L" 个目标" << std::endl;

    // 显示关键结果摘要
    displayDiagnosticSummary(result);

    // 询问用户报告选项
    std::wcout << L"\n=== 生成诊断报告 ===" << std::endl;
    std::wcout << L"请选择要生成的报告格式:" << std::endl;
    std::wcout << L"1. 仅生成文本报告 (.txt)" << std::endl;
    std::wcout << L"2. 仅生成HTML报告 (.html)" << std::endl;
    std::wcout << L"3. 生成两种格式的报告" << std::endl;
    std::wcout << L"4. 不生成报告" << std::endl;
    std::wcout << L"请输入选择 (1-4): ";

    std::wstring format_choice;
    std::getline(std::wcin, format_choice);

    if (format_choice == L"4") {
        std::wcout << L"诊断完成，未生成报告。" << std::endl;
        return;
    }

    std::wcout << L"\n请选择报告保存位置:" << std::endl;
    std::wcout << L"1. 桌面 (推荐)" << std::endl;
    std::wcout << L"2. 自定义路径" << std::endl;
    std::wcout << L"请输入选择 (1-2): ";

    std::wstring path_choice;
    std::getline(std::wcin, path_choice);

    std::filesystem::path output_path_fs;

    if (path_choice == L"2") {
        std::wcout << L"请输入完整的输出目录路径: ";
        std::wstring custom_path;
        std::getline(std::wcin, custom_path);

        output_path_fs = std::filesystem::path(custom_path);

        // 验证路径是否存在
        if (!std::filesystem::exists(output_path_fs)) {
            std::wcout << L"指定的路径不存在，将使用桌面作为默认路径。" << std::endl;
            output_path_fs.clear();
        }
    }

    // 如果没有指定路径或路径无效，使用桌面
    if (output_path_fs.empty()) {
        wchar_t* desktop_path = nullptr;
        if (SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &desktop_path) == S_OK) {
            output_path_fs = std::filesystem::path(desktop_path);
            CoTaskMemFree(desktop_path);
        }
        else {
            output_path_fs = std::filesystem::path(L"C:\\Users\\Public\\Desktop");
        }
        std::wcout << L"将报告保存到桌面: " << output_path_fs.wstring() << std::endl;
    }

    // 生成时间戳
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    localtime_s(&tm_buf, &time_t);

    wchar_t time_buffer[32];
    wcsftime(time_buffer, sizeof(time_buffer) / sizeof(wchar_t), L"%Y%m%d_%H%M%S", &tm_buf);

    // 创建基础文件名（选择一种）
    std::wstring base_name = L"NetworkDiagnostic_" + std::wstring(time_buffer); // 英文版本
    // std::wstring base_name = L"网络诊断报告_" + std::wstring(time_buffer);   // 中文版本

    bool success = false;
    std::vector<std::filesystem::path> generated_files;

    // 生成文本报告
    if (format_choice == L"1" || format_choice == L"3") {
        std::wcout << L"\n正在生成文本报告..." << std::endl;

        auto txt_path = output_path_fs / (base_name + L".txt");
        std::string utf8_txt_path = txt_path.string();  // 自动处理编码

        DiagnosticResult txt_result = g_networkDiagnostic->generateReport(result, utf8_txt_path);
        if (txt_result.isSuccess()) {
            std::wcout << L"✅ 文本报告已生成: " << txt_path.wstring() << std::endl;
            generated_files.push_back(txt_path);
            success = true;
        }
        else {
            std::wcout << L"❌ 文本报告生成失败: "
                << utf8_to_wstring(txt_result.error_message) << std::endl;
        }
    }

    // 生成HTML报告
    if (format_choice == L"2" || format_choice == L"3") {
        std::wcout << L"\n正在生成HTML报告..." << std::endl;

        auto html_path = output_path_fs / (base_name + L".html");
        std::string utf8_html_path = html_path.string();  // 自动处理编码

        DiagnosticResult html_result = g_networkDiagnostic->generateHTMLReport(result, utf8_html_path);
        if (html_result.isSuccess()) {
            std::wcout << L"✅ HTML报告已生成: " << html_path.wstring() << std::endl;
            generated_files.push_back(html_path);
            success = true;

            // 询问是否打开HTML报告
            std::wcout << L"\n是否立即打开HTML报告查看? (y/n): ";
            std::wstring open_choice;
            std::getline(std::wcin, open_choice);
            if (open_choice == L"y" || open_choice == L"Y" || open_choice == L"是") {
                ShellExecute(NULL, L"open", html_path.wstring().c_str(), NULL, NULL, SW_SHOWNORMAL);
                std::wcout << L"正在打开HTML报告..." << std::endl;
            }
        }
        else {
            std::wcout << L"❌ HTML报告生成失败: "
                << utf8_to_wstring(html_result.error_message) << std::endl;
        }
    }

    // 最终结果
    if (success) {
        std::wcout << L"\n🎉 网络诊断报告生成完成!" << std::endl;
        std::wcout << L"共生成 " << generated_files.size() << L" 个报告文件。" << std::endl;

        // 询问是否打开报告所在文件夹
        std::wcout << L"\n是否打开报告所在文件夹? (y/n): ";
        std::wstring folder_choice;
        std::getline(std::wcin, folder_choice);
        if (folder_choice == L"y" || folder_choice == L"Y" || folder_choice == L"是") {
            ShellExecute(NULL, L"open", output_path_fs.wstring().c_str(), NULL, NULL, SW_SHOWNORMAL);
        }
    }
    else {
        std::wcout << L"\n❌ 报告生成失败，请检查磁盘空间和文件权限。" << std::endl;
    }
}



// --- 初始化与辅助函数 ---
void initializeManagers() {
    try {
        std::filesystem::path exe_dir = get_executable_dir();
        std::filesystem::path model_path = exe_dir / L"crnn_model.onnx";

        if (std::filesystem::exists(model_path)) {
            g_zfwManager = std::make_unique<ZfwManager>(model_path.wstring());
            std::wcout << L"✓ ZfwManager 初始化成功。" << std::endl;
        }
        else {
            std::wcout << L"⚠ 警告: 模型文件 'crnn_model.onnx' 未找到，'login' 功能将不可用。" << std::endl;
        }

        g_dnsManager = std::make_unique<DNSManager>();
        std::wcout << L"✓ DNSManager 初始化成功。" << std::endl;
        g_networkDiagnostic = std::make_unique<NetworkDiagnostic>();
        std::wcout << L"✓ NetworkDiagnostic 初始化成功。" << std::endl;
    }
    catch (const std::exception& e) {
        std::wcout << L"✗ 初始化管理器时发生错误: " << utf8_to_wstring(e.what()) << std::endl;
    }
    catch (...) {
        std::wcout << L"✗ 初始化管理器时发生未知错误。" << std::endl;
    }
}

std::wstring get_executable_dir() {
    wchar_t path[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return std::filesystem::path(path).parent_path().wstring();
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsGroup = NULL;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(administratorsGroup);
    }
    return isAdmin == TRUE;
}