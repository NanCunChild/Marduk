#include "pch.h"
#include "DNSManager.h"
#include <Windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <regex>
#include <filesystem>
#include <sstream>

#pragma comment(lib, "advapi32.lib")

const char* SERVICE_NAME = "AcrylicDNSProxySvc";

class DNSManager::DnsManagerImpl {
public:
    std::string acrylic_dir;
    std::string service_exe_path;
    std::string hosts_path;
    DnsServiceInfo service_info;
    bool is_initialized = false;

    DnsManagerImpl() {
        initializePaths();
    }

    void initializePaths() {
        char exe_path_buffer[MAX_PATH];
        GetModuleFileNameA(NULL, exe_path_buffer, MAX_PATH);
        acrylic_dir = std::string(exe_path_buffer);
        acrylic_dir = acrylic_dir.substr(0, acrylic_dir.find_last_of("\\/"));
        service_exe_path = acrylic_dir + "\\AcrylicService.exe";
        hosts_path = acrylic_dir + "\\AcrylicHosts.txt";

        service_info.service_path = service_exe_path;
        service_info.hosts_file_path = hosts_path;
    }

    DnsResult initialize() {
        // 检查必要文件
        if (!std::filesystem::exists(service_exe_path)) {
            return DnsResult(DnsErrorCode::FILE_NOT_FOUND,
                "AcrylicService.exe not found at: " + service_exe_path);
        }

        // 更新服务状态
        updateServiceStatus();
        is_initialized = true;

        return DnsResult(DnsErrorCode::SUCCESS, "DNS Manager initialized successfully");
    }

    void updateServiceStatus() {
        service_info.is_installed = isServiceInstalledImpl();
        service_info.is_running = isServiceRunningImpl();
        service_info.rule_count = countRulesImpl();
    }

    bool isServiceInstalledImpl() {
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!scm) return false;

        SC_HANDLE service = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        bool installed = (service != NULL);

        if (service) CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return installed;
    }

    bool isServiceRunningImpl() {
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!scm) return false;

        SC_HANDLE service = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }

        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded;
        bool running = false;

        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
            running = (ssp.dwCurrentState == SERVICE_RUNNING);
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return running;
    }

    int countRulesImpl() {
        if (!std::filesystem::exists(hosts_path)) {
            return 0;
        }

        std::ifstream file(hosts_path);
        if (!file.is_open()) {
            return -1; // 无法读取
        }

        std::string line;
        int count = 0;
        while (std::getline(file, line)) {
            // 简单计数非空行且非注释行
            line.erase(0, line.find_first_not_of(" \t"));
            if (!line.empty() && line[0] != '#') {
                count++;
            }
        }
        return count;
    }

    DnsResult installServiceImpl() {
        if (isServiceInstalledImpl()) {
            return DnsResult(DnsErrorCode::SUCCESS, "Service already installed");
        }

        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!scm) {
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED) {
                return DnsResult(DnsErrorCode::PERMISSION_ADMIN_REQUIRED,
                    "Administrator privileges required to install service");
            }
            return DnsResult(DnsErrorCode::SYSTEM_SCM_ACCESS_FAILED,
                "Failed to access Service Control Manager");
        }

        SC_HANDLE service = CreateServiceA(
            scm,
            SERVICE_NAME,
            "Acrylic DNS Proxy",
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            service_exe_path.c_str(),
            NULL, NULL, NULL, NULL, NULL
        );

        if (!service) {
            DWORD error = GetLastError();
            CloseServiceHandle(scm);

            if (error == ERROR_ACCESS_DENIED) {
                return DnsResult(DnsErrorCode::PERMISSION_ADMIN_REQUIRED,
                    "Administrator privileges required");
            }
            return DnsResult(DnsErrorCode::SERVICE_INSTALL_FAILED,
                "Failed to create service, error code: " + std::to_string(error));
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        updateServiceStatus();

        return DnsResult(DnsErrorCode::SUCCESS, "Service installed successfully");
    }

    DnsResult uninstallServiceImpl() {
        if (!isServiceInstalledImpl()) {
            return DnsResult(DnsErrorCode::SUCCESS, "Service is not installed");
        }

        // 先停止服务
        stopServiceImpl();

        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!scm) {
            return DnsResult(DnsErrorCode::SYSTEM_SCM_ACCESS_FAILED,
                "Failed to access Service Control Manager");
        }

        SC_HANDLE service = OpenServiceA(scm, SERVICE_NAME, DELETE);
        if (!service) {
            CloseServiceHandle(scm);
            return DnsResult(DnsErrorCode::SERVICE_NOT_FOUND,
                "Service not found for deletion");
        }

        if (!DeleteService(service)) {
            DWORD error = GetLastError();
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return DnsResult(DnsErrorCode::SERVICE_UNINSTALL_FAILED,
                "Failed to delete service, error code: " + std::to_string(error));
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        updateServiceStatus();

        return DnsResult(DnsErrorCode::SUCCESS, "Service uninstalled successfully");
    }

    DnsResult startServiceImpl() {
        if (!isServiceInstalledImpl()) {
            return DnsResult(DnsErrorCode::SERVICE_NOT_FOUND,
                "Service is not installed");
        }

        if (isServiceRunningImpl()) {
            return DnsResult(DnsErrorCode::SERVICE_ALREADY_RUNNING,
                "Service is already running");
        }

        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!scm) {
            return DnsResult(DnsErrorCode::SYSTEM_SCM_ACCESS_FAILED,
                "Failed to access Service Control Manager");
        }

        SC_HANDLE service = OpenServiceA(scm, SERVICE_NAME, SERVICE_START);
        if (!service) {
            CloseServiceHandle(scm);
            return DnsResult(DnsErrorCode::SYSTEM_SERVICE_HANDLE_FAILED,
                "Failed to open service");
        }

        if (!StartService(service, 0, NULL)) {
            DWORD error = GetLastError();
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return DnsResult(DnsErrorCode::SERVICE_START_FAILED,
                "Failed to start service, error code: " + std::to_string(error));
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        updateServiceStatus();

        return DnsResult(DnsErrorCode::SUCCESS, "Service started successfully");
    }

    DnsResult stopServiceImpl() {
        if (!isServiceInstalledImpl()) {
            return DnsResult(DnsErrorCode::SERVICE_NOT_FOUND,
                "Service is not installed");
        }

        if (!isServiceRunningImpl()) {
            return DnsResult(DnsErrorCode::SERVICE_ALREADY_STOPPED,
                "Service is already stopped");
        }

        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!scm) {
            return DnsResult(DnsErrorCode::SYSTEM_SCM_ACCESS_FAILED,
                "Failed to access Service Control Manager");
        }

        SC_HANDLE service = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP);
        if (!service) {
            CloseServiceHandle(scm);
            return DnsResult(DnsErrorCode::SYSTEM_SERVICE_HANDLE_FAILED,
                "Failed to open service");
        }

        SERVICE_STATUS status;
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
            DWORD error = GetLastError();
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return DnsResult(DnsErrorCode::SERVICE_STOP_FAILED,
                "Failed to stop service, error code: " + std::to_string(error));
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        updateServiceStatus();

        return DnsResult(DnsErrorCode::SUCCESS, "Service stopped successfully");
    }

    // 验证IP地址格式
    bool isValidIP(const std::string& ip) {
        static const std::regex pattern(
            R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
        );
        return std::regex_match(ip, pattern);
    }

    // 验证主机名格式
    bool isValidHostname(const std::string& hostname) {
        if (hostname.empty() || hostname.length() > 253) return false;
        static const std::regex pattern(
            R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$)"
        );
        return std::regex_match(hostname, pattern);
    }

    DnsResult addRuleImpl(const std::string& ip, const std::string& hostname) {
        // 验证输入
        if (!isValidIP(ip)) {
            return DnsResult(DnsErrorCode::CONFIG_INVALID_IP,
                "Invalid IP address format: " + ip);
        }

        if (!isValidHostname(hostname)) {
            return DnsResult(DnsErrorCode::CONFIG_INVALID_HOSTNAME,
                "Invalid hostname format: " + hostname);
        }

        // 检查文件是否可写
        std::ofstream hosts_file(hosts_path, std::ios::app);
        if (!hosts_file.is_open()) {
            return DnsResult(DnsErrorCode::FILE_WRITE_FAILED,
                "Failed to open hosts file: " + hosts_path);
        }

        // 添加规则
        hosts_file << "\n" << ip << "\t" << hostname;
        hosts_file.close();

        updateServiceStatus();
        return DnsResult(DnsErrorCode::SUCCESS,
            "Rule added successfully: " + ip + " -> " + hostname);
    }

    DnsResult removeRuleImpl(const std::string& hostname) {
        if (!isValidHostname(hostname)) {
            return DnsResult(DnsErrorCode::CONFIG_INVALID_HOSTNAME,
                "Invalid hostname format: " + hostname);
        }

        if (!std::filesystem::exists(hosts_path)) {
            return DnsResult(DnsErrorCode::FILE_NOT_FOUND,
                "Hosts file not found: " + hosts_path);
        }

        // 读取现有文件
        std::ifstream input_file(hosts_path);
        if (!input_file.is_open()) {
            return DnsResult(DnsErrorCode::FILE_READ_FAILED,
                "Failed to read hosts file: " + hosts_path);
        }

        std::vector<std::string> lines;
        std::string line;
        bool found = false;

        while (std::getline(input_file, line)) {
            // 检查这一行是否包含要删除的hostname
            std::string trimmed_line = line;
            trimmed_line.erase(0, trimmed_line.find_first_not_of(" \t"));

            if (!trimmed_line.empty() && trimmed_line[0] != '#') {
                // 分割IP和hostname
                std::istringstream iss(trimmed_line);
                std::string ip, host;
                if (iss >> ip >> host && host == hostname) {
                    found = true;
                    continue; // 跳过这一行，即删除它
                }
            }
            lines.push_back(line);
        }
        input_file.close();

        if (!found) {
            return DnsResult(DnsErrorCode::CONFIG_RULE_EXISTS,
                "Rule for hostname '" + hostname + "' not found");
        }

        // 写回文件
        std::ofstream output_file(hosts_path, std::ios::trunc);
        if (!output_file.is_open()) {
            return DnsResult(DnsErrorCode::FILE_WRITE_FAILED,
                "Failed to write to hosts file: " + hosts_path);
        }

        for (const auto& saved_line : lines) {
            output_file << saved_line << "\n";
        }
        output_file.close();

        updateServiceStatus();
        return DnsResult(DnsErrorCode::SUCCESS,
            "Rule for hostname '" + hostname + "' removed successfully");
    }

    DnsResult clearAllRulesImpl() {
        // 简单地清空文件
        std::ofstream output_file(hosts_path, std::ios::trunc);
        if (!output_file.is_open()) {
            return DnsResult(DnsErrorCode::FILE_WRITE_FAILED,
                "Failed to clear hosts file: " + hosts_path);
        }

        // 写入基本注释
        output_file << "# Acrylic DNS Proxy Hosts File\n";
        output_file << "# Format: IP_ADDRESS    HOSTNAME\n";
        output_file << "# Example: 127.0.0.1    example.com\n\n";
        output_file.close();

        updateServiceStatus();
        return DnsResult(DnsErrorCode::SUCCESS,
            "All DNS rules cleared successfully");
    }

    DnsResult listRulesImpl(std::vector<std::pair<std::string, std::string>>& rules) {
        rules.clear();

        if (!std::filesystem::exists(hosts_path)) {
            return DnsResult(DnsErrorCode::SUCCESS, "No hosts file found, no rules to list");
        }

        std::ifstream file(hosts_path);
        if (!file.is_open()) {
            return DnsResult(DnsErrorCode::FILE_READ_FAILED,
                "Failed to read hosts file: " + hosts_path);
        }

        std::string line;
        while (std::getline(file, line)) {
            // 去除前导空白
            line.erase(0, line.find_first_not_of(" \t"));

            // 跳过空行和注释行
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // 解析IP和hostname
            std::istringstream iss(line);
            std::string ip, hostname;
            if (iss >> ip >> hostname) {
                rules.emplace_back(ip, hostname);
            }
        }
        file.close();

        return DnsResult(DnsErrorCode::SUCCESS,
            "Listed " + std::to_string(rules.size()) + " DNS rules");
    }
};


DNSManager::DNSManager() : impl(std::make_unique<DnsManagerImpl>()) {
}

DNSManager::~DNSManager() = default;

DnsResult DNSManager::initialize() {
    return impl->initialize();
}

DnsServiceInfo DNSManager::getServiceInfo() const {
    impl->updateServiceStatus();
    return impl->service_info;
}

DnsResult DNSManager::installService() {
    return impl->installServiceImpl();
}

DnsResult DNSManager::uninstallService() {
    return impl->uninstallServiceImpl();
}

DnsResult DNSManager::startService() {
    return impl->startServiceImpl();
}

DnsResult DNSManager::stopService() {
    return impl->stopServiceImpl();
}

DnsResult DNSManager::restartService() {
    auto stop_result = stopService();
    if (!stop_result.isSuccess() && stop_result.error_code != DnsErrorCode::SERVICE_ALREADY_STOPPED) {
        return stop_result;
    }

    // 等待服务完全停止，这里之后可以改为检查状态或者事件等待
    Sleep(2000);

    return startService();
}

DnsResult DNSManager::addRule(const std::string& ip, const std::string& hostname) {
    return impl->addRuleImpl(ip, hostname);
}

DnsResult DNSManager::removeRule(const std::string& hostname) {
    return impl->removeRuleImpl(hostname);
}

DnsResult DNSManager::clearAllRules() {
    return impl->clearAllRulesImpl();
}

DnsResult DNSManager::listRules(std::vector<std::pair<std::string, std::string>>& rules) {
    return impl->listRulesImpl(rules);
}

bool DNSManager::isReady() const {
    return impl->is_initialized && impl->service_info.is_installed;
}