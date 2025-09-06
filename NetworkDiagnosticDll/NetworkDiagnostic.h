#pragma once

#ifdef NETWORKDIAGNOSTICDLL_EXPORTS
#define NETWORKDIAGNOSTIC_API __declspec(dllexport)
#else
#define NETWORKDIAGNOSTIC_API __declspec(dllimport)
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#pragma warning(disable: 4275)
#endif


#include <string>
#include <vector>
#include <memory>

// 网络诊断错误码
enum class NETWORKDIAGNOSTIC_API DiagnosticErrorCode : int {
    SUCCESS = 0,

    // 文件错误 (3000-3099)
    FILE_CREATE_FAILED = 3001,
    FILE_WRITE_FAILED = 3002,
    FILE_PATH_INVALID = 3003,

    // 系统错误 (3100-3199)
    SYSTEM_WMI_ACCESS_FAILED = 3101,
    SYSTEM_REGISTRY_ACCESS_FAILED = 3102,
    SYSTEM_NETWORK_INFO_FAILED = 3103,
    SYSTEM_PERMISSION_DENIED = 3104,

    // 网络测试错误 (3200-3299)
    NETWORK_PING_FAILED = 3201,
    NETWORK_DNS_QUERY_FAILED = 3202,
    NETWORK_CONNECTION_FAILED = 3203,
    NETWORK_TIMEOUT = 3204,

    // 配置错误 (3300-3399)
    CONFIG_INVALID_TARGET = 3301,
    CONFIG_INVALID_PATH = 3302,

    // 其他错误
    SYSTEM_UNKNOWN_ERROR = 3999
};

// 网络接口信息
struct NETWORKDIAGNOSTIC_API NetworkInterface {
    std::string name;
    std::string description;
    std::string mac_address;
    std::string ip_address;
    std::string subnet_mask;
    std::string gateway;
    std::string dns_servers;
    bool is_enabled;
    std::string connection_type; // Ethernet, WiFi, etc.
    uint64_t bytes_sent;
    uint64_t bytes_received;
};

// 代理配置信息
struct NETWORKDIAGNOSTIC_API ProxyConfig {
    bool proxy_enabled;
    std::string proxy_server;
    std::string proxy_port;
    std::string proxy_bypass;
    bool auto_detect;
    std::string auto_config_url;
};

// 路由信息
struct NETWORKDIAGNOSTIC_API RouteInfo {
    std::string destination;
    std::string netmask;
    std::string gateway;
    std::string route_interface;
    int metric;
};

// Ping测试结果
struct NETWORKDIAGNOSTIC_API PingResult {
    std::string target;
    bool success;
    int packet_loss_percent;
    double min_time_ms;
    double max_time_ms;
    double avg_time_ms;
    std::string error_message;
};

// DNS查询结果
struct NETWORKDIAGNOSTIC_API DnsQueryResult {
    std::string hostname;
    std::vector<std::string> ip_addresses;
    bool success;
    double query_time_ms;
    std::string dns_server_used;
    std::string error_message;
};

// TCP连接测试结果
struct NETWORKDIAGNOSTIC_API TcpConnectionResult {
    std::string target_host;
    int target_port;
    bool success;
    double connection_time_ms;
    std::string error_message;
};

// 诊断配置
struct NETWORKDIAGNOSTIC_API DiagnosticConfig {
    std::vector<std::string> ping_targets = {
        "8.8.8.8", "114.114.114.114", "223.5.5.5",
        "baidu.com", "google.com"
    };
    std::vector<std::string> dns_test_domains = {
        "baidu.com", "google.com", "github.com",
        "xidian.edu.cn"
    };
    std::vector<std::pair<std::string, int>> tcp_test_targets = {
        {"baidu.com", 80}, {"baidu.com", 443},
        {"google.com", 80}, {"google.com", 443}
    };
    int ping_timeout_ms = 3000;
    int tcp_timeout_ms = 5000;
    int dns_timeout_ms = 3000;
};

// 诊断结果
struct NETWORKDIAGNOSTIC_API DiagnosticResult {
    DiagnosticErrorCode error_code;
    std::string error_message;

    // 系统信息
    std::string system_info;
    std::string timestamp;

    // 网络配置
    std::vector<NetworkInterface> network_interfaces;
    ProxyConfig proxy_config;
    std::vector<RouteInfo> routing_table;

    // 测试结果
    std::vector<PingResult> ping_results;
    std::vector<DnsQueryResult> dns_results;
    std::vector<TcpConnectionResult> tcp_results;

    DiagnosticResult(DiagnosticErrorCode code = DiagnosticErrorCode::SUCCESS,
        const std::string& message = "")
        : error_code(code), error_message(message) {
    }

    bool isSuccess() const { return error_code == DiagnosticErrorCode::SUCCESS; }
};

// 网络诊断管理器
class NETWORKDIAGNOSTIC_API NetworkDiagnostic {
public:
    NetworkDiagnostic();
    ~NetworkDiagnostic();

    // 执行完整诊断
    DiagnosticResult runFullDiagnostic(const DiagnosticConfig& config = DiagnosticConfig{});

    // 单独的诊断功能
    DiagnosticResult getNetworkInterfaces(std::vector<NetworkInterface>& interfaces);
    DiagnosticResult getProxyConfig(ProxyConfig& config);
    DiagnosticResult getRoutingTable(std::vector<RouteInfo>& routes);

    // 网络测试功能
    DiagnosticResult pingTest(const std::vector<std::string>& targets, std::vector<PingResult>& results);
    DiagnosticResult dnsTest(const std::vector<std::string>& domains, std::vector<DnsQueryResult>& results);
    DiagnosticResult tcpTest(const std::vector<std::pair<std::string, int>>& targets, std::vector<TcpConnectionResult>& results);

    // 报告生成
    DiagnosticResult generateReport(const DiagnosticResult& result, const std::string& output_path);
    DiagnosticResult generateHTMLReport(const DiagnosticResult& result, const std::string& output_path);

private:
    class NetworkDiagnosticImpl;
    std::unique_ptr<NetworkDiagnosticImpl> impl;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif