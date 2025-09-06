#pragma once

#ifdef DNSMANAGERDLL_EXPORTS
#define DNS_API __declspec(dllexport)
#else
#define DNS_API __declspec(dllimport)
#endif

#include <string>
#include <vector>
#include <memory>

enum class DnsErrorCode : int {
    SUCCESS = 0,

    // 权限错误 (2000-2099)
    PERMISSION_DENIED = 2001,
    PERMISSION_ADMIN_REQUIRED = 2002,

    // 服务错误 (2100-2199)
    SERVICE_NOT_FOUND = 2101,
    SERVICE_INSTALL_FAILED = 2102,
    SERVICE_UNINSTALL_FAILED = 2103,
    SERVICE_START_FAILED = 2104,
    SERVICE_STOP_FAILED = 2105,
    SERVICE_ALREADY_RUNNING = 2106,
    SERVICE_ALREADY_STOPPED = 2107,

    // 文件错误 (2200-2299)
    FILE_NOT_FOUND = 2201,
    FILE_ACCESS_DENIED = 2202,
    FILE_WRITE_FAILED = 2203,
    FILE_READ_FAILED = 2204,

    // 配置错误 (2300-2399)
    CONFIG_INVALID_IP = 2301,
    CONFIG_INVALID_HOSTNAME = 2302,
    CONFIG_RULE_EXISTS = 2303,

    // 系统错误 (2900-2999)
    SYSTEM_SCM_ACCESS_FAILED = 2901,
    SYSTEM_SERVICE_HANDLE_FAILED = 2902,
    SYSTEM_UNKNOWN_ERROR = 2999
};

struct DnsResult {
    DnsErrorCode error_code;
    std::string error_message;

    DnsResult(DnsErrorCode code = DnsErrorCode::SUCCESS, const std::string& message = "")
        : error_code(code), error_message(message) {
    }

    bool isSuccess() const { return error_code == DnsErrorCode::SUCCESS; }
};

// DNS服务状态信息
struct DnsServiceInfo {
    bool is_installed = false;
    bool is_running = false;
    std::string service_path;
    std::string hosts_file_path;
    int rule_count = 0;
};


class DNS_API DNSManager {
public:
    DNSManager();
    ~DNSManager();

    DnsResult initialize();
    DnsServiceInfo getServiceInfo() const;

    bool isReady() const;

    DnsResult installService();
    DnsResult uninstallService();
    DnsResult startService();
    DnsResult stopService();
    DnsResult restartService();

    DnsResult addRule(const std::string& ip, const std::string& hostname);
    DnsResult removeRule(const std::string& hostname);
    DnsResult clearAllRules();
    DnsResult listRules(std::vector<std::pair<std::string, std::string>>& rules);

private:
    class DnsManagerImpl;
    std::unique_ptr<DnsManagerImpl> impl;
};