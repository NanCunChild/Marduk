#include "pch.h"
#include "NetworkDiagnostic.h"
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <wininet.h>
#include <winhttp.h>
#include <windns.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <regex>
#include <numeric>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "icmp.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "dnsapi.lib")

class NetworkDiagnostic::NetworkDiagnosticImpl {
public:
    NetworkDiagnosticImpl() {
        // 初始化 Winsock
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~NetworkDiagnosticImpl() {
        WSACleanup();
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    std::string getSystemInfo() {
        std::ostringstream oss;

        // 获取操作系统版本
        OSVERSIONINFOEX osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

        // 获取计算机名
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);

        oss << "Computer Name: " << computerName << "\n";
        oss << "Windows Version: " << GetVersion() << "\n";

        // 获取内存信息
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);

        oss << "Total Physical Memory: " << (memInfo.ullTotalPhys / 1024 / 1024) << " MB\n";
        oss << "Available Physical Memory: " << (memInfo.ullAvailPhys / 1024 / 1024) << " MB\n";

        return oss.str();
    }

    DiagnosticResult getNetworkInterfacesImpl(std::vector<NetworkInterface>& interfaces) {
        interfaces.clear();

        DWORD dwSize = 0;
        DWORD dwRetVal = 0;

        // 获取所需的缓冲区大小
        if (GetAdaptersInfo(NULL, &dwSize) != ERROR_BUFFER_OVERFLOW) {
            return DiagnosticResult(DiagnosticErrorCode::SYSTEM_NETWORK_INFO_FAILED,
                "Failed to get network adapter info buffer size");
        }

        PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwSize);
        if (pAdapterInfo == NULL) {
            return DiagnosticResult(DiagnosticErrorCode::SYSTEM_NETWORK_INFO_FAILED,
                "Memory allocation failed");
        }

        dwRetVal = GetAdaptersInfo(pAdapterInfo, &dwSize);
        if (dwRetVal != NO_ERROR) {
            free(pAdapterInfo);
            return DiagnosticResult(DiagnosticErrorCode::SYSTEM_NETWORK_INFO_FAILED,
                "GetAdaptersInfo failed with error: " + std::to_string(dwRetVal));
        }

        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            NetworkInterface iface;
            iface.name = pAdapter->AdapterName;
            iface.description = pAdapter->Description;

            // MAC地址
            std::ostringstream mac_oss;
            for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                if (i > 0) mac_oss << "-";
                mac_oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
                    << (int)pAdapter->Address[i];
            }
            iface.mac_address = mac_oss.str();

            // IP信息
            iface.ip_address = pAdapter->IpAddressList.IpAddress.String;
            iface.subnet_mask = pAdapter->IpAddressList.IpMask.String;
            iface.gateway = pAdapter->GatewayList.IpAddress.String;

            // 连接类型
            switch (pAdapter->Type) {
            case MIB_IF_TYPE_ETHERNET: iface.connection_type = "Ethernet"; break;
            case IF_TYPE_IEEE80211: iface.connection_type = "WiFi"; break;
            case MIB_IF_TYPE_PPP: iface.connection_type = "PPP"; break;
            default: iface.connection_type = "Other"; break;
            }

            iface.is_enabled = (strcmp(iface.ip_address.c_str(), "0.0.0.0") != 0);

            // 获取流量统计（需要额外的API调用）
            iface.bytes_sent = 0;
            iface.bytes_received = 0;

            interfaces.push_back(iface);
            pAdapter = pAdapter->Next;
        }

        free(pAdapterInfo);
        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "Retrieved " + std::to_string(interfaces.size()) + " network interfaces");
    }

    DiagnosticResult getProxyConfigImpl(ProxyConfig& config) {
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
        ZeroMemory(&proxyConfig, sizeof(proxyConfig));

        if (!WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
            return DiagnosticResult(DiagnosticErrorCode::SYSTEM_REGISTRY_ACCESS_FAILED,
                "Failed to get IE proxy configuration");
        }

        config.auto_detect = (proxyConfig.fAutoDetect == TRUE);

        if (proxyConfig.lpszAutoConfigUrl) {
            std::wstring wstr(proxyConfig.lpszAutoConfigUrl);
            config.auto_config_url = std::string(wstr.begin(), wstr.end());
        }

        if (proxyConfig.lpszProxy) {
            std::wstring wstr(proxyConfig.lpszProxy);
            std::string proxy_str(wstr.begin(), wstr.end());

            // 解析代理服务器和端口
            size_t colon_pos = proxy_str.find(':');
            if (colon_pos != std::string::npos) {
                config.proxy_server = proxy_str.substr(0, colon_pos);
                config.proxy_port = proxy_str.substr(colon_pos + 1);
                config.proxy_enabled = true;
            }
        }

        if (proxyConfig.lpszProxyBypass) {
            std::wstring wstr(proxyConfig.lpszProxyBypass);
            config.proxy_bypass = std::string(wstr.begin(), wstr.end());
        }

        // 清理内存
        if (proxyConfig.lpszAutoConfigUrl) GlobalFree(proxyConfig.lpszAutoConfigUrl);
        if (proxyConfig.lpszProxy) GlobalFree(proxyConfig.lpszProxy);
        if (proxyConfig.lpszProxyBypass) GlobalFree(proxyConfig.lpszProxyBypass);

        return DiagnosticResult(DiagnosticErrorCode::SUCCESS, "Proxy configuration retrieved");
    }

    DiagnosticResult getRoutingTableImpl(std::vector<RouteInfo>& routes) {
        routes.clear();

        DWORD dwSize = 0;
        DWORD dwRetVal = GetIpForwardTable(NULL, &dwSize, 0);
        if (dwRetVal != ERROR_INSUFFICIENT_BUFFER) {
            return DiagnosticResult(DiagnosticErrorCode::SYSTEM_NETWORK_INFO_FAILED,
                "Failed to get routing table size");
        }

        PMIB_IPFORWARDTABLE pIpForwardTable = (MIB_IPFORWARDTABLE*)malloc(dwSize);
        if (pIpForwardTable == NULL) {
            return DiagnosticResult(DiagnosticErrorCode::SYSTEM_NETWORK_INFO_FAILED,
                "Memory allocation failed for routing table");
        }

        dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 0);
        if (dwRetVal != NO_ERROR) {
            free(pIpForwardTable);
            return DiagnosticResult(DiagnosticErrorCode::SYSTEM_NETWORK_INFO_FAILED,
                "GetIpForwardTable failed with error: " + std::to_string(dwRetVal));
        }

        for (DWORD i = 0; i < pIpForwardTable->dwNumEntries; i++) {
            MIB_IPFORWARDROW* pRow = &pIpForwardTable->table[i];

            RouteInfo route;

            // 转换IP地址
            struct in_addr addr;
            addr.S_un.S_addr = pRow->dwForwardDest;
            route.destination = inet_ntoa(addr);

            addr.S_un.S_addr = pRow->dwForwardMask;
            route.netmask = inet_ntoa(addr);

            addr.S_un.S_addr = pRow->dwForwardNextHop;
            route.gateway = inet_ntoa(addr);

            route.metric = pRow->dwForwardMetric1;
            route.route_interface = std::to_string(pRow->dwForwardIfIndex);

            routes.push_back(route);
        }

        free(pIpForwardTable);
        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "Retrieved " + std::to_string(routes.size()) + " routing entries");
    }

    DiagnosticResult pingTestImpl(const std::vector<std::string>& targets, std::vector<PingResult>& results) {
        results.clear();

        HANDLE hIcmpFile = IcmpCreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE) {
            return DiagnosticResult(DiagnosticErrorCode::NETWORK_PING_FAILED,
                "Unable to create ICMP handle");
        }

        char SendData[] = "Hello World!";
        DWORD ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
        LPVOID ReplyBuffer = (VOID*)malloc(ReplySize);

        for (const auto& target : targets) {
            PingResult result;
            result.target = target;

            // 解析主机名为IP
            struct addrinfo* addr_result = NULL;
            struct addrinfo hints;
            ZeroMemory(&hints, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            IPAddr ipaddr = INADDR_NONE;
            if (getaddrinfo(target.c_str(), NULL, &hints, &addr_result) == 0) {
                struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)addr_result->ai_addr;
                ipaddr = sockaddr_ipv4->sin_addr.s_addr;
                freeaddrinfo(addr_result);
            }
            else {
                ipaddr = inet_addr(target.c_str());
            }

            if (ipaddr == INADDR_NONE) {
                result.success = false;
                result.error_message = "Could not resolve hostname";
                results.push_back(result);
                continue;
            }

            // 执行多次ping取平均值
            std::vector<double> times;
            int successful_pings = 0;
            const int ping_count = 4;

            for (int i = 0; i < ping_count; i++) {
                DWORD dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),
                    NULL, ReplyBuffer, ReplySize, 3000);

                if (dwRetVal != 0) {
                    PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
                    if (pEchoReply->Status == IP_SUCCESS) {
                        times.push_back(pEchoReply->RoundTripTime);
                        successful_pings++;
                    }
                }
                Sleep(100); // 间隔100ms
            }

            if (successful_pings > 0) {
                result.success = true;
                result.packet_loss_percent = ((ping_count - successful_pings) * 100) / ping_count;
                result.min_time_ms = *std::min_element(times.begin(), times.end());
                result.max_time_ms = *std::max_element(times.begin(), times.end());
                result.avg_time_ms = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
            }
            else {
                result.success = false;
                result.packet_loss_percent = 100;
                result.error_message = "All ping packets lost";
            }

            results.push_back(result);
        }

        free(ReplyBuffer);
        IcmpCloseHandle(hIcmpFile);

        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "Ping test completed for " + std::to_string(targets.size()) + " targets");
    }

    DiagnosticResult dnsTestImpl(const std::vector<std::string>& domains, std::vector<DnsQueryResult>& results) {
        results.clear();

        for (const auto& domain : domains) {
            DnsQueryResult result;
            result.hostname = domain;

            auto start_time = std::chrono::high_resolution_clock::now();

            // 使用Windows DNS API查询
            PDNS_RECORD pDnsRecord;
            DNS_STATUS status = DnsQuery_A(domain.c_str(), DNS_TYPE_A, DNS_QUERY_STANDARD,
                NULL, &pDnsRecord, NULL);

            auto end_time = std::chrono::high_resolution_clock::now();
            result.query_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

            if (status == 0 && pDnsRecord) {
                result.success = true;

                PDNS_RECORD pNext = pDnsRecord;
                while (pNext) {
                    if (pNext->wType == DNS_TYPE_A) {
                        struct in_addr addr;
                        addr.s_addr = pNext->Data.A.IpAddress;
                        result.ip_addresses.push_back(inet_ntoa(addr));
                    }
                    pNext = pNext->pNext;
                }

                DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
            }
            else {
                result.success = false;
                result.error_message = "DNS query failed with status: " + std::to_string(status);
            }

            // 获取使用的DNS服务器（简化版）
            result.dns_server_used = "System Default";

            results.push_back(result);
        }

        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "DNS test completed for " + std::to_string(domains.size()) + " domains");
    }

    DiagnosticResult tcpTestImpl(const std::vector<std::pair<std::string, int>>& targets,
        std::vector<TcpConnectionResult>& results) {
        results.clear();

        for (const auto& target : targets) {
            TcpConnectionResult result;
            result.target_host = target.first;
            result.target_port = target.second;

            auto start_time = std::chrono::high_resolution_clock::now();

            // 创建套接字
            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                result.success = false;
                result.error_message = "Failed to create socket";
                results.push_back(result);
                continue;
            }

            // 设置超时
            DWORD timeout = 5000; // 5秒
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

            // 解析主机名
            struct addrinfo* addr_result = NULL;
            struct addrinfo hints;
            ZeroMemory(&hints, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            std::string port_str = std::to_string(target.second);
            int getaddr_result = getaddrinfo(target.first.c_str(), port_str.c_str(), &hints, &addr_result);

            if (getaddr_result != 0) {
                result.success = false;
                result.error_message = "Failed to resolve hostname";
                closesocket(sock);
                results.push_back(result);
                continue;
            }

            // 尝试连接
            int connect_result = connect(sock, addr_result->ai_addr, (int)addr_result->ai_addrlen);

            auto end_time = std::chrono::high_resolution_clock::now();
            result.connection_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

            if (connect_result == 0) {
                result.success = true;
            }
            else {
                result.success = false;
                result.error_message = "Connection failed with error: " + std::to_string(WSAGetLastError());
            }

            freeaddrinfo(addr_result);
            closesocket(sock);
            results.push_back(result);
        }

        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "TCP test completed for " + std::to_string(targets.size()) + " targets");
    }

    DiagnosticResult runFullDiagnosticImpl(const DiagnosticConfig& config) {
        DiagnosticResult result;
        result.timestamp = getCurrentTimestamp();
        result.system_info = getSystemInfo();

        // 获取网络配置
        auto interfaces_result = getNetworkInterfacesImpl(result.network_interfaces);
        if (!interfaces_result.isSuccess()) {
            return interfaces_result;
        }

        auto proxy_result = getProxyConfigImpl(result.proxy_config);
        // 代理配置失败不是致命错误，继续执行

        auto routing_result = getRoutingTableImpl(result.routing_table);
        // 路由表获取失败也不是致命错误

        // 执行网络测试
        auto ping_result = pingTestImpl(config.ping_targets, result.ping_results);
        auto dns_result = dnsTestImpl(config.dns_test_domains, result.dns_results);
        auto tcp_result = tcpTestImpl(config.tcp_test_targets, result.tcp_results);

        result.error_code = DiagnosticErrorCode::SUCCESS;
        result.error_message = "Full diagnostic completed successfully";

        return result;
    }

    DiagnosticResult generateReportImpl(const DiagnosticResult& diagnostic_result, const std::string& output_path) {
        std::ofstream file(output_path);
        if (!file.is_open()) {
            return DiagnosticResult(DiagnosticErrorCode::FILE_CREATE_FAILED,
                "Failed to create report file: " + output_path);
        }

        file << "===== 网络诊断报告 =====\n";
        file << "生成时间: " << diagnostic_result.timestamp << "\n\n";

        // 系统信息
        file << "=== 系统信息 ===\n";
        file << diagnostic_result.system_info << "\n";

        // 网络接口
        file << "=== 网络接口 ===\n";
        for (const auto& iface : diagnostic_result.network_interfaces) {
            file << "接口: " << iface.description << "\n";
            file << "  名称: " << iface.name << "\n";
            file << "  MAC地址: " << iface.mac_address << "\n";
            file << "  IP地址: " << iface.ip_address << "\n";
            file << "  子网掩码: " << iface.subnet_mask << "\n";
            file << "  网关: " << iface.gateway << "\n";
            file << "  类型: " << iface.connection_type << "\n";
            file << "  状态: " << (iface.is_enabled ? "启用" : "禁用") << "\n\n";
        }

        // 代理配置
        file << "=== 代理配置 ===\n";
        file << "代理启用: " << (diagnostic_result.proxy_config.proxy_enabled ? "是" : "否") << "\n";
        if (diagnostic_result.proxy_config.proxy_enabled) {
            file << "代理服务器: " << diagnostic_result.proxy_config.proxy_server << "\n";
            file << "代理端口: " << diagnostic_result.proxy_config.proxy_port << "\n";
        }
        file << "自动检测: " << (diagnostic_result.proxy_config.auto_detect ? "是" : "否") << "\n";
        if (!diagnostic_result.proxy_config.auto_config_url.empty()) {
            file << "自动配置URL: " << diagnostic_result.proxy_config.auto_config_url << "\n";
        }
        file << "\n";

        // Ping测试结果
        file << "=== Ping 测试结果 ===\n";
        for (const auto& ping : diagnostic_result.ping_results) {
            file << "目标: " << ping.target << "\n";
            file << "  成功: " << (ping.success ? "是" : "否") << "\n";
            if (ping.success) {
                file << "  丢包率: " << ping.packet_loss_percent << "%\n";
                file << "  最小时间: " << ping.min_time_ms << "ms\n";
                file << "  最大时间: " << ping.max_time_ms << "ms\n";
                file << "  平均时间: " << ping.avg_time_ms << "ms\n";
            }
            else {
                file << "  错误: " << ping.error_message << "\n";
            }
            file << "\n";
        }

        // DNS测试结果
        file << "=== DNS 测试结果 ===\n";
        for (const auto& dns : diagnostic_result.dns_results) {
            file << "域名: " << dns.hostname << "\n";
            file << "  成功: " << (dns.success ? "是" : "否") << "\n";
            file << "  查询时间: " << dns.query_time_ms << "ms\n";
            if (dns.success) {
                file << "  IP地址:\n";
                for (const auto& ip : dns.ip_addresses) {
                    file << "    " << ip << "\n";
                }
                file << "  使用的DNS服务器: " << dns.dns_server_used << "\n";
            }
            else {
                file << "  错误: " << dns.error_message << "\n";
            }
            file << "\n";
        }

        // TCP连接测试结果
        file << "=== TCP 连接测试结果 ===\n";
        for (const auto& tcp : diagnostic_result.tcp_results) {
            file << "目标: " << tcp.target_host << ":" << tcp.target_port << "\n";
            file << "  成功: " << (tcp.success ? "是" : "否") << "\n";
            file << "  连接时间: " << tcp.connection_time_ms << "ms\n";
            if (!tcp.success) {
                file << "  错误: " << tcp.error_message << "\n";
            }
            file << "\n";
        }

        // 路由表
        file << "=== 路由表 ===\n";
        file << "目标地址\t\t子网掩码\t\t网关\t\t接口\t跃点数\n";
        for (const auto& route : diagnostic_result.routing_table) {
            file << route.destination << "\t\t"
                << route.netmask << "\t\t"
                << route.gateway << "\t\t"
                << route.route_interface << "\t"
                << route.metric << "\n";
        }

        file.close();

        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "Text report generated successfully: " + output_path);
    }

    DiagnosticResult generateHTMLReportImpl(const DiagnosticResult& diagnostic_result, const std::string& output_path) {
        std::ofstream file(output_path);
        if (!file.is_open()) {
            return DiagnosticResult(DiagnosticErrorCode::FILE_CREATE_FAILED,
                "Failed to create HTML report file: " + output_path);
        }

        file << R"(<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>网络诊断报告</title>
    <style>
        body { font-family: 'Microsoft YaHei', sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .info-box { background-color: #ecf0f1; padding: 15px; border-left: 4px solid #3498db; margin: 10px 0; }
        .success { color: #27ae60; font-weight: bold; }
        .error { color: #e74c3c; font-weight: bold; }
        .warning { color: #f39c12; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background-color: #ecf0f1; border-radius: 5px; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 网络诊断报告</h1>
        <div class="info-box">
            <strong>生成时间:</strong> <span class="timestamp">)" << diagnostic_result.timestamp << R"(</span>
        </div>
)";

        // 系统信息
        file << R"(        <h2>🖥️ 系统信息</h2>
        <div class="info-box">
            <pre>)" << diagnostic_result.system_info << R"(</pre>
        </div>
)";

        // 网络接口
        file << R"(        <h2>🌐 网络接口</h2>
        <table>
            <tr>
                <th>接口名称</th>
                <th>描述</th>
                <th>MAC地址</th>
                <th>IP地址</th>
                <th>子网掩码</th>
                <th>网关</th>
                <th>类型</th>
                <th>状态</th>
            </tr>
)";

        for (const auto& iface : diagnostic_result.network_interfaces) {
            file << "            <tr>\n"
                << "                <td>" << iface.name << "</td>\n"
                << "                <td>" << iface.description << "</td>\n"
                << "                <td>" << iface.mac_address << "</td>\n"
                << "                <td>" << iface.ip_address << "</td>\n"
                << "                <td>" << iface.subnet_mask << "</td>\n"
                << "                <td>" << iface.gateway << "</td>\n"
                << "                <td>" << iface.connection_type << "</td>\n"
                << "                <td><span class=\"" << (iface.is_enabled ? "success\">启用" : "error\">禁用") << "</span></td>\n"
                << "            </tr>\n";
        }
        file << "        </table>\n";

        // 代理配置
        file << R"(        <h2>🔄 代理配置</h2>
        <div class="info-box">
            <p><strong>代理启用:</strong> <span class=")" << (diagnostic_result.proxy_config.proxy_enabled ? "success\">是" : "error\">否") << R"(</span></p>
)";
        if (diagnostic_result.proxy_config.proxy_enabled) {
            file << "            <p><strong>代理服务器:</strong> " << diagnostic_result.proxy_config.proxy_server << "</p>\n"
                << "            <p><strong>代理端口:</strong> " << diagnostic_result.proxy_config.proxy_port << "</p>\n";
        }
        file << "            <p><strong>自动检测:</strong> <span class=\"" << (diagnostic_result.proxy_config.auto_detect ? "success\">是" : "error\">否") << "</span></p>\n";
        if (!diagnostic_result.proxy_config.auto_config_url.empty()) {
            file << "            <p><strong>自动配置URL:</strong> " << diagnostic_result.proxy_config.auto_config_url << "</p>\n";
        }
        file << "        </div>\n";

        // Ping测试结果
        file << R"(        <h2>📡 Ping 测试结果</h2>
        <table>
            <tr>
                <th>目标</th>
                <th>状态</th>
                <th>丢包率</th>
                <th>最小延迟</th>
                <th>最大延迟</th>
                <th>平均延迟</th>
                <th>错误信息</th>
            </tr>
)";

        for (const auto& ping : diagnostic_result.ping_results) {
            file << "            <tr>\n"
                << "                <td>" << ping.target << "</td>\n"
                << "                <td><span class=\"" << (ping.success ? "success\">成功" : "error\">失败") << "</span></td>\n";

            if (ping.success) {
                file << "                <td>" << ping.packet_loss_percent << "%</td>\n"
                    << "                <td>" << std::fixed << std::setprecision(1) << ping.min_time_ms << "ms</td>\n"
                    << "                <td>" << std::fixed << std::setprecision(1) << ping.max_time_ms << "ms</td>\n"
                    << "                <td>" << std::fixed << std::setprecision(1) << ping.avg_time_ms << "ms</td>\n"
                    << "                <td>-</td>\n";
            }
            else {
                file << "                <td>100%</td>\n"
                    << "                <td>-</td>\n"
                    << "                <td>-</td>\n"
                    << "                <td>-</td>\n"
                    << "                <td><span class=\"error\">" << ping.error_message << "</span></td>\n";
            }
            file << "            </tr>\n";
        }
        file << "        </table>\n";

        // DNS测试结果
        file << R"(        <h2>🌍 DNS 测试结果</h2>
        <table>
            <tr>
                <th>域名</th>
                <th>状态</th>
                <th>查询时间</th>
                <th>解析IP</th>
                <th>DNS服务器</th>
                <th>错误信息</th>
            </tr>
)";

        for (const auto& dns : diagnostic_result.dns_results) {
            file << "            <tr>\n"
                << "                <td>" << dns.hostname << "</td>\n"
                << "                <td><span class=\"" << (dns.success ? "success\">成功" : "error\">失败") << "</span></td>\n"
                << "                <td>" << std::fixed << std::setprecision(1) << dns.query_time_ms << "ms</td>\n";

            if (dns.success) {
                file << "                <td>";
                for (size_t i = 0; i < dns.ip_addresses.size(); ++i) {
                    if (i > 0) file << "<br>";
                    file << dns.ip_addresses[i];
                }
                file << "</td>\n"
                    << "                <td>" << dns.dns_server_used << "</td>\n"
                    << "                <td>-</td>\n";
            }
            else {
                file << "                <td>-</td>\n"
                    << "                <td>-</td>\n"
                    << "                <td><span class=\"error\">" << dns.error_message << "</span></td>\n";
            }
            file << "            </tr>\n";
        }
        file << "        </table>\n";

        // TCP连接测试结果
        file << R"(        <h2>🔌 TCP 连接测试结果</h2>
        <table>
            <tr>
                <th>目标主机</th>
                <th>端口</th>
                <th>状态</th>
                <th>连接时间</th>
                <th>错误信息</th>
            </tr>
)";

        for (const auto& tcp : diagnostic_result.tcp_results) {
            file << "            <tr>\n"
                << "                <td>" << tcp.target_host << "</td>\n"
                << "                <td>" << tcp.target_port << "</td>\n"
                << "                <td><span class=\"" << (tcp.success ? "success\">成功" : "error\">失败") << "</span></td>\n"
                << "                <td>" << std::fixed << std::setprecision(1) << tcp.connection_time_ms << "ms</td>\n";

            if (tcp.success) {
                file << "                <td>-</td>\n";
            }
            else {
                file << "                <td><span class=\"error\">" << tcp.error_message << "</span></td>\n";
            }
            file << "            </tr>\n";
        }
        file << "        </table>\n";

        // 路由表
        if (!diagnostic_result.routing_table.empty()) {
            file << R"(        <h2>🛣️ 路由表</h2>
        <table>
            <tr>
                <th>目标地址</th>
                <th>子网掩码</th>
                <th>网关</th>
                <th>接口</th>
                <th>跃点数</th>
            </tr>
)";

            for (const auto& route : diagnostic_result.routing_table) {
                file << "            <tr>\n"
                    << "                <td>" << route.destination << "</td>\n"
                    << "                <td>" << route.netmask << "</td>\n"
                    << "                <td>" << route.gateway << "</td>\n"
                    << "                <td>" << route.route_interface << "</td>\n"
                    << "                <td>" << route.metric << "</td>\n"
                    << "            </tr>\n";
            }
            file << "        </table>\n";
        }

        file << R"(        <hr style="margin-top: 40px;">
        <p class="timestamp">
            报告由西电校园网辅助工具生成 | 
            诊断时间: )" << diagnostic_result.timestamp << R"(
        </p>
    </div>
</body>
</html>)";

        file.close();

        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "HTML report generated successfully: " + output_path);
    }
};

// NetworkDiagnostic 公开接口实现
NetworkDiagnostic::NetworkDiagnostic()
    : impl(std::make_unique<NetworkDiagnosticImpl>()) {
}

NetworkDiagnostic::~NetworkDiagnostic() = default;

DiagnosticResult NetworkDiagnostic::runFullDiagnostic(const DiagnosticConfig& config) {
    return impl->runFullDiagnosticImpl(config);
}

DiagnosticResult NetworkDiagnostic::getNetworkInterfaces(std::vector<NetworkInterface>& interfaces) {
    return impl->getNetworkInterfacesImpl(interfaces);
}

DiagnosticResult NetworkDiagnostic::getProxyConfig(ProxyConfig& config) {
    return impl->getProxyConfigImpl(config);
}

DiagnosticResult NetworkDiagnostic::getRoutingTable(std::vector<RouteInfo>& routes) {
    return impl->getRoutingTableImpl(routes);
}

DiagnosticResult NetworkDiagnostic::pingTest(const std::vector<std::string>& targets, std::vector<PingResult>& results) {
    return impl->pingTestImpl(targets, results);
}

DiagnosticResult NetworkDiagnostic::dnsTest(const std::vector<std::string>& domains, std::vector<DnsQueryResult>& results) {
    return impl->dnsTestImpl(domains, results);
}

DiagnosticResult NetworkDiagnostic::tcpTest(const std::vector<std::pair<std::string, int>>& targets, std::vector<TcpConnectionResult>& results) {
    return impl->tcpTestImpl(targets, results);
}

DiagnosticResult NetworkDiagnostic::generateReport(const DiagnosticResult& result, const std::string& output_path) {
    return impl->generateReportImpl(result, output_path);
}

DiagnosticResult NetworkDiagnostic::generateHTMLReport(const DiagnosticResult& result, const std::string& output_path) {
    return impl->generateHTMLReportImpl(result, output_path);
}