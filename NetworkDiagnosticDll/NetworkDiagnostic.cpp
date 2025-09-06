#include "pch.h"
#include "NetworkDiagnostic.h"
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <wininet.h>
#include <windns.h>
#include <winhttp.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <numeric>
#include <thread>
#include <regex>
#include <iomanip>

// 定义宏以允许使用废弃的Winsock API（临时解决方案）
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
//#pragma comment(lib, "icmp.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "dnsapi.lib")

typedef HANDLE(WINAPI* IcmpCreateFileFunc)(VOID);
typedef BOOL(WINAPI* IcmpCloseHandleFunc)(HANDLE);
typedef DWORD(WINAPI* IcmpSendEchoFunc)(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);

class ICMPHelper {
private:
    HMODULE hIcmpDll;
    IcmpCreateFileFunc pIcmpCreateFile;
    IcmpCloseHandleFunc pIcmpCloseHandle;
    IcmpSendEchoFunc pIcmpSendEcho;
    bool initialization_success;

public:
    ICMPHelper() : hIcmpDll(nullptr), pIcmpCreateFile(nullptr),
        pIcmpCloseHandle(nullptr), pIcmpSendEcho(nullptr),
        initialization_success(false) {
        try {
            // 尝试加载ICMP.DLL
            hIcmpDll = LoadLibraryA("ICMP.DLL");
            if (hIcmpDll) {
                pIcmpCreateFile = (IcmpCreateFileFunc)GetProcAddress(hIcmpDll, "IcmpCreateFile");
                pIcmpCloseHandle = (IcmpCloseHandleFunc)GetProcAddress(hIcmpDll, "IcmpCloseHandle");
                pIcmpSendEcho = (IcmpSendEchoFunc)GetProcAddress(hIcmpDll, "IcmpSendEcho");

                // 检查所有函数是否成功加载
                if (pIcmpCreateFile && pIcmpCloseHandle && pIcmpSendEcho) {
                    initialization_success = true;
                }
            }
        }
        catch (...) {
            cleanup();
        }
    }

    ~ICMPHelper() {
        cleanup();
    }

private:
    void cleanup() {
        if (hIcmpDll) {
            FreeLibrary(hIcmpDll);
            hIcmpDll = nullptr;
        }
        pIcmpCreateFile = nullptr;
        pIcmpCloseHandle = nullptr;
        pIcmpSendEcho = nullptr;
        initialization_success = false;
    }

public:
    bool IsAvailable() const {
        return initialization_success && hIcmpDll && pIcmpCreateFile && pIcmpCloseHandle && pIcmpSendEcho;
    }

    bool IsInitialized() const {
        return initialization_success;
    }

    HANDLE CreateFile() {
        if (IsAvailable() && pIcmpCreateFile) {
            return pIcmpCreateFile();
        }
        return INVALID_HANDLE_VALUE;
    }

    BOOL CloseHandle(HANDLE hIcmpFile) {
        if (IsAvailable() && pIcmpCloseHandle) {
            return pIcmpCloseHandle(hIcmpFile);
        }
        return FALSE;
    }

    DWORD SendEcho(HANDLE hIcmpFile, IPAddr DestinationAddress, LPVOID RequestData,
        WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions,
        LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) {
        if (IsAvailable() && pIcmpSendEcho) {
            return pIcmpSendEcho(hIcmpFile, DestinationAddress, RequestData, RequestSize,
                RequestOptions, ReplyBuffer, ReplySize, Timeout);
        }
        return 0;
    }
};

class NetworkDiagnostic::NetworkDiagnosticImpl {
private:
    std::unique_ptr<ICMPHelper> icmpHelper;

public:
    NetworkDiagnosticImpl() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        try {
            icmpHelper = std::make_unique<ICMPHelper>();
        }
        catch (...) {
            icmpHelper = nullptr;
        }
    }

    ~NetworkDiagnosticImpl() {
        WSACleanup();
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        std::tm tm_buf;
        localtime_s(&tm_buf, &time_t);
        oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    std::string getSystemInfo() {
        std::ostringstream oss;

        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);
        oss << "Computer Name: " << computerName << "\n";

        // 通过注册表获取Windows版本信息
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            char buffer[256];
            DWORD bufferSize = sizeof(buffer);

            // 产品名称
            if (RegQueryValueExA(hKey, "ProductName", NULL, NULL,
                (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                oss << "Windows Version: " << buffer << "\n";
            }

            // 版本号
            bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "CurrentVersion", NULL, NULL,
                (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                oss << "Version Number: " << buffer << "\n";
            }

            // 构建号
            bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL,
                (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                oss << "Build Number: " << buffer << "\n";
            }

            RegCloseKey(hKey);
        }
        else {
            // 降级方案：使用GetVersion()
            DWORD version = 0;
            DWORD majorVersion = (DWORD)(LOBYTE(LOWORD(version)));
            DWORD minorVersion = (DWORD)(HIBYTE(LOWORD(version)));
            oss << "Windows Version: " << majorVersion << "." << minorVersion << "\n";
        }

        // 获取内存信息
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);

        oss << "Total Physical Memory: " << (memInfo.ullTotalPhys / 1024 / 1024) << " MB\n";
        oss << "Available Physical Memory: " << (memInfo.ullAvailPhys / 1024 / 1024) << " MB\n";

        return oss.str();
    }

    // 添加现代的IP地址转换辅助函数
    std::string ipv4ToString(DWORD ipAddress) {
        char buffer[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = ipAddress;

        if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN) != NULL) {
            return std::string(buffer);
        }
        else {
            // 降级方案：手动转换
            unsigned char* bytes = (unsigned char*)&ipAddress;
            std::ostringstream oss;
            oss << (int)bytes[0] << "." << (int)bytes[1] << "."
                << (int)bytes[2] << "." << (int)bytes[3];
            return oss.str();
        }
    }

    DWORD stringToIPv4(const std::string& ipString) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ipString.c_str(), &addr) == 1) {
            return addr.s_addr;
        }
        else {
            return INADDR_NONE;
        }
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
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, proxyConfig.lpszAutoConfigUrl, -1, NULL, 0, NULL, NULL);
            if (size_needed > 0) {
                std::string result(size_needed - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, proxyConfig.lpszAutoConfigUrl, -1, &result[0], size_needed, NULL, NULL);
                config.auto_config_url = result;
            }
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

            // 使用现代的IP地址转换函数
            route.destination = ipv4ToString(pRow->dwForwardDest);
            route.netmask = ipv4ToString(pRow->dwForwardMask);
            route.gateway = ipv4ToString(pRow->dwForwardNextHop);

            route.metric = pRow->dwForwardMetric1;
            route.route_interface = std::to_string(pRow->dwForwardIfIndex);

            routes.push_back(route);
        }

        free(pIpForwardTable);
        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "Retrieved " + std::to_string(routes.size()) + " routing entries");
    }

    DiagnosticResult icmpApiPing(const std::string& target, PingResult& result) {
        result.target = target;
        result.success = false;

        if (!icmpHelper) {
            result.error_message = "ICMP Helper not initialized";
            return DiagnosticResult(DiagnosticErrorCode::NETWORK_PING_FAILED,
                "ICMP Helper not initialized");
        }

        if (!icmpHelper -> IsAvailable()) {
            return DiagnosticResult(DiagnosticErrorCode::NETWORK_PING_FAILED,
                "ICMP API not available");
        }

        HANDLE hIcmpFile = icmpHelper->CreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE) {
            return DiagnosticResult(DiagnosticErrorCode::NETWORK_PING_FAILED,
                "Unable to create ICMP handle");
        }

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
            ipaddr = stringToIPv4(target);
        }

        if (ipaddr == INADDR_NONE) {
            icmpHelper->CloseHandle(hIcmpFile);
            result.error_message = "Could not resolve hostname";
            return DiagnosticResult(DiagnosticErrorCode::NETWORK_PING_FAILED,
                "Hostname resolution failed");
        }

        char SendData[] = "Hello World!";
        DWORD ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
        LPVOID ReplyBuffer = (VOID*)malloc(ReplySize);

        if (!ReplyBuffer) {
            icmpHelper->CloseHandle(hIcmpFile);
            return DiagnosticResult(DiagnosticErrorCode::SYSTEM_NETWORK_INFO_FAILED,
                "Memory allocation failed");
        }

        std::vector<double> times;
        int successful_pings = 0;
        const int ping_count = 4;

        for (int i = 0; i < ping_count; i++) {
            DWORD dwRetVal = icmpHelper->SendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),
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

        free(ReplyBuffer);
        icmpHelper->CloseHandle(hIcmpFile);

        return DiagnosticResult(DiagnosticErrorCode::SUCCESS, "ICMP API ping completed");
    }

    DiagnosticResult pingTestImpl(const std::vector<std::string>& targets, std::vector<PingResult>& results) {
        results.clear();

        for (const auto& target : targets) {
            PingResult result;
            DiagnosticResult ping_result = icmpApiPing(target, result);

            // 即使单个ping失败，也要将结果添加到列表中
            results.push_back(result);

            // 如果有严重错误，记录但继续处理其他目标
            if (!ping_result.isSuccess() && ping_result.error_code != DiagnosticErrorCode::NETWORK_PING_FAILED) {
                // 可以在这里记录警告，但继续处理其他目标
            }
        }

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
                        // 使用现代的IP地址转换
                        result.ip_addresses.push_back(ipv4ToString(pNext->Data.A.IpAddress));
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
        //auto ping_result = rawSocketPingImpl(config.ping_targets, result.ping_results);
		//auto ping_result = icmpApiPing(config.ping_targets, result.ping_results);
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
        std::ofstream file(output_path, std::ios::out | std::ios::binary);
        if (!file.is_open()) {
            return DiagnosticResult(DiagnosticErrorCode::FILE_CREATE_FAILED,
                "Failed to create HTML report file: " + output_path);
        }

        std::string html_content = u8R"(<!DOCTYPE html>
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
        <h1>[诊断] 网络诊断报告</h1>
        <div class="info-box">
            <strong>生成时间:</strong> <span class="timestamp">)";

        html_content += diagnostic_result.timestamp;
        html_content += u8R"(</span><br>
            <strong>报告版本:</strong> <span class="timestamp">西电校园网辅助工具 v1.0</span>
        </div>
)";

        // 系统信息
        html_content += u8R"(
        <h2>💻 系统信息</h2>
        <div class="info-box">
            <pre>)";
        html_content += diagnostic_result.system_info;
        html_content += u8"</pre>\n        </div>\n";

        // 网络接口
        html_content += u8R"(
        <h2>🌐 网络接口</h2>
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
            html_content += u8"            <tr>\n";
            html_content += u8"                <td>" + iface.name + "</td>\n";
            html_content += u8"                <td>" + iface.description + "</td>\n";
            html_content += u8"                <td>" + iface.mac_address + "</td>\n";
            html_content += u8"                <td>" + iface.ip_address + "</td>\n";
            html_content += u8"                <td>" + iface.subnet_mask + "</td>\n";
            html_content += u8"                <td>" + iface.gateway + "</td>\n";
            html_content += u8"                <td>" + iface.connection_type + "</td>\n";
            if (iface.is_enabled) {
                html_content += u8"                <td><span class=\"status-badge badge-success\">启用</span></td>\n";
            }
            else {
                html_content += u8"                <td><span class=\"status-badge badge-error\">禁用</span></td>\n";
            }
            html_content += u8"            </tr>\n";
        }
        html_content += u8"        </table>\n";

        // 代理配置
        html_content += u8R"(
        <h2>🔄 代理配置</h2>
        <div class="info-box">
            <p><strong>🔧 代理状态:</strong> <span class=")";
        html_content += (diagnostic_result.proxy_config.proxy_enabled ? u8"success\">已启用" : u8"error\">未启用");
        html_content += u8"</span></p>\n";

        if (diagnostic_result.proxy_config.proxy_enabled) {
            html_content += u8"            <p><strong>🌐 代理服务器:</strong> <code>" + diagnostic_result.proxy_config.proxy_server + "</code></p>\n";
            html_content += u8"            <p><strong>🔌 代理端口:</strong> <code>" + diagnostic_result.proxy_config.proxy_port + "</code></p>\n";
        }

        html_content += u8"            <p><strong>🔍 自动检测:</strong> <span class=\"" +
            std::string(diagnostic_result.proxy_config.auto_detect ? u8"success\">已启用" : u8"error\">未启用") +
            u8"</span></p>\n";

        if (!diagnostic_result.proxy_config.auto_config_url.empty()) {
            html_content += u8"            <p><strong>⚙️ 自动配置URL:</strong> <code>" + diagnostic_result.proxy_config.auto_config_url + "</code></p>\n";
        }
        html_content += u8"        </div>\n";

        // Ping测试结果
        html_content += u8R"(
        <h2>📡 连通性测试结果</h2>
        <table>
            <tr>
                <th>目标地址</th>
                <th>状态</th>
                <th>丢包率</th>
                <th>最小延迟</th>
                <th>最大延迟</th>
                <th>平均延迟</th>
                <th>错误信息</th>
            </tr>
        )";

        for (const auto& ping : diagnostic_result.ping_results) {
            html_content += u8"            <tr>\n";
            html_content += u8"                <td><code>" + ping.target + "</code></td>\n";
            html_content += u8"                <td><span class=\"" + std::string(ping.success ? u8"success\">连接成功" : u8"error\">连接失败") + u8"</span></td>\n";

            if (ping.success) {
                html_content += u8"                <td><span class=\"metric-value\">" + std::to_string(ping.packet_loss_percent) + "%</span></td>\n";
                html_content += u8"                <td><span class=\"ping-time\">" + std::to_string((int)ping.min_time_ms) + "ms</span></td>\n";
                html_content += u8"                <td><span class=\"ping-time\">" + std::to_string((int)ping.max_time_ms) + "ms</span></td>\n";
                html_content += u8"                <td><span class=\"ping-time\">" + std::to_string((int)ping.avg_time_ms) + "ms</span></td>\n";
                html_content += u8"                <td>-</td>\n";
            }
            else {
                html_content += u8"                <td><span class=\"error\">100%</span></td>\n";
                html_content += u8"                <td>-</td>\n";
                html_content += u8"                <td>-</td>\n";
                html_content += u8"                <td>-</td>\n";
                html_content += u8"                <td><span class=\"error\">" + ping.error_message + "</span></td>\n";
            }
            html_content += u8"            </tr>\n";
        }
        html_content += u8"        </table>\n";

        // DNS测试结果
        html_content += u8R"(
        <h2>🌍 DNS解析测试结果</h2>
        <table>
            <tr>
                <th>域名</th>
                <th>状态</th>
                <th>查询时间</th>
                <th>解析IP地址</th>
                <th>DNS服务器</th>
                <th>错误信息</th>
            </tr>
        )";

        for (const auto& dns : diagnostic_result.dns_results) {
            html_content += u8"            <tr>\n";
            html_content += u8"                <td><strong>" + dns.hostname + u8"</strong></td>\n";

            if (dns.success) {
                html_content += u8"                <td><span class=\"success\">解析成功</span></td>\n";
            }
            else {
                html_content += u8"                <td><span class=\"error\">解析失败</span></td>\n";
            }

            html_content += u8"                <td><span class=\"ping-time\">" + std::to_string((int)dns.query_time_ms) + u8"ms</span></td>\n";

            if (dns.success) {
                html_content += u8"                <td>";
                for (size_t i = 0; i < dns.ip_addresses.size(); ++i) {
                    if (i > 0) html_content += u8"<br>";
                    html_content += u8"<code>" + dns.ip_addresses[i] + u8"</code>";
                }
                html_content += u8"</td>\n";
                html_content += u8"                <td><code>" + dns.dns_server_used + u8"</code></td>\n";
                html_content += u8"                <td>-</td>\n";
            }
            else {
                html_content += u8"                <td>-</td>\n";
                html_content += u8"                <td>-</td>\n";
                html_content += u8"                <td><span class=\"error\">" + dns.error_message + u8"</span></td>\n";
            }
            html_content += u8"            </tr>\n";
        }
        html_content += u8"        </table>\n";

        // TCP连接测试结果
        html_content += u8R"(
        <h2>🔌 TCP连接测试结果</h2>
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
            html_content += u8"            <tr>\n";
            html_content += u8"                <td><strong>" + tcp.target_host + u8"</strong></td>\n";
            html_content += u8"                <td><span class=\"metric-value\">" + std::to_string(tcp.target_port) + u8"</span></td>\n";

            if (tcp.success) {
                html_content += u8"                <td><span class=\"success\">连接成功</span></td>\n";
            }
            else {
                html_content += u8"                <td><span class=\"error\">连接失败</span></td>\n";
            }

            html_content += u8"                <td><span class=\"ping-time\">" + std::to_string((int)tcp.connection_time_ms) + u8"ms</span></td>\n";

            if (tcp.success) {
                html_content += u8"                <td>-</td>\n";
            }
            else {
                html_content += u8"                <td><span class=\"error\">" + tcp.error_message + u8"</span></td>\n";
            }
            html_content += u8"            </tr>\n";
        }
        html_content += u8"        </table>\n";

        // 路由表
        if (!diagnostic_result.routing_table.empty()) {
            html_content += u8R"(
        <h2>🛣️ 路由表信息</h2>
        <table>
            <tr>
                <th>目标网络</th>
                <th>子网掩码</th>
                <th>网关地址</th>
                <th>网络接口</th>
                <th>路由跃点</th>
            </tr>
)";

            for (const auto& route : diagnostic_result.routing_table) {
                html_content += u8"            <tr>\n";
                html_content += u8"                <td><code>" + route.destination + "</code></td>\n";
                html_content += u8"                <td><code>" + route.netmask + "</code></td>\n";
                html_content += u8"                <td><code>" + route.gateway + "</code></td>\n";
                html_content += u8"                <td><span class=\"metric-value\">" + route.route_interface + "</span></td>\n";
                html_content += u8"                <td><span class=\"metric-value\">" + std::to_string(route.metric) + "</span></td>\n";
                html_content += u8"            </tr>\n";
            }
            html_content += u8"        </table>\n";
        }


        html_content += u8R"(
        <div class="footer">
            <h3 style="color: #2c3e50; margin-bottom: 20px;">📋 诊断报告说明</h3>
            <div style="text-align: left; max-width: 800px; margin: 0 auto;">
                <p><strong>🔍 连通性测试:</strong> 检测与目标服务器的网络连接状态</p>
                <p><strong>🌍 DNS解析:</strong> 验证域名解析服务是否正常工作</p>
                <p><strong>🔌 TCP连接:</strong> 测试特定端口的连接可用性</p>
                <p><strong>🌐 网络接口:</strong> 显示系统中所有网络适配器的状态</p>
                <p><strong>🛣️ 路由信息:</strong> 展示网络数据包的转发路径配置</p>
            </div>
            <hr style="margin: 30px 0; border: none; height: 1px; background: linear-gradient(90deg, transparent, #bdc3c7, transparent);">
            <div style="margin-top: 30px;">
                <p style="font-size: 1.1em; font-weight: 600; color: #2c3e50; margin-bottom: 15px;">
                    📊 西电校园网辅助工具 - 网络诊断报告
                </p>
                <p class="timestamp" style="font-size: 0.9em; margin: 5px 0;">
                    🕐 生成时间: )";
        html_content += diagnostic_result.timestamp;
        html_content += u8R"(
                </p>
                <p class="timestamp" style="font-size: 0.9em; margin: 5px 0;">
                    🔧 诊断引擎: NetworkDiagnostic v1.0
                </p>
                <p class="timestamp" style="font-size: 0.9em; margin: 5px 0;">
                    💡 如遇网络问题，请根据测试结果检查相应配置
                </p>
                <div style="margin-top: 25px; padding: 20px; background: linear-gradient(135deg, #e8f5e8 0%, #f0f8ff 100%); border-radius: 10px; border-left: 4px solid #27ae60;">
                    <h4 style="color: #27ae60; margin-bottom: 15px;">✅ 诊断建议</h4>
                    <div style="text-align: left; font-size: 0.9em; line-height: 1.6;">
        )";

        // 添加诊断建议
        bool has_network_issues = false;
        std::vector<std::string> suggestions;

        //// 检查连通性问题
        //if (successful_pings < diagnostic_result.ping_results.size() / 2) {
        //    has_network_issues = true;
        //    suggestions.push_back("🔴 网络连接异常：建议检查网络连接状态、防火墙设置或联系网络管理员");
        //}

        //// 检查DNS问题
        //if (successful_dns < diagnostic_result.dns_results.size() / 2) {
        //    has_network_issues = true;
        //    suggestions.push_back("🟡 DNS解析异常：建议更换DNS服务器(如8.8.8.8)或检查DNS配置");
        //}

        //// 检查TCP连接问题
        //if (successful_tcp < diagnostic_result.tcp_results.size() / 2) {
        //    has_network_issues = true;
        //    suggestions.push_back("🟠 TCP连接异常：建议检查目标服务器状态或端口可用性");
        //}

        //// 检查活跃接口
        //if (active_interfaces == 0) {
        //    has_network_issues = true;
        //    suggestions.push_back("🔴 无活跃网络接口：请检查网络适配器驱动或物理连接");
        //}

        if (!has_network_issues) {
            html_content += u8"                        <p style=\"color: #27ae60;\">🎉 网络状态良好！所有测试项目基本正常。</p>\n";
        }
        else {
            for (const auto& suggestion : suggestions) {
                html_content += u8"                        <p>• " + suggestion + "</p>\n";
            }
        }

        html_content += u8R"(                    </div>
                </div>
            </div>
        </div>
        
        <!-- 返回顶部按钮 -->
        <div style="position: fixed; bottom: 30px; right: 30px; z-index: 1000;">
            <button onclick="scrollToTop() " style = "
            background: linear - gradient(135deg, #667eea 0 %, #764ba2 100 %);
    border: none;
    color: white;
    padding: 15px;
        border - radius: 50 %;
    cursor: pointer;
        box - shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        font - size: 18px;
    width: 50px;
    height: 50px;
    transition: all 0.3s ease;
        " onmouseover="this.style.transform = 'scale(1.1)'" onmouseout="this.style.transform = 'scale(1)'">
            ↑
            < / button>
            < / div>
            < / div>

            <script>
            // 返回顶部功能
            function scrollToTop() {
            window.scrollTo({
                top: 0,
                behavior : 'smooth'
                });
        }

        // 页面加载完成后的动画效果
        document.addEventListener('DOMContentLoaded', function() {
            // 为表格行添加渐入动画
            const tableRows = document.querySelectorAll('tr');
            tableRows.forEach((row, index) = > {
                row.style.opacity = '0';
                row.style.transform = 'translateY(20px)';
                row.style.transition = 'opacity 0.5s ease, transform 0.5s ease';

                setTimeout(() = > {
                    row.style.opacity = '1';
                    row.style.transform = 'translateY(0)';
                }, index * 50);
            });

            // 为摘要卡片添加动画
            const summaryCards = document.querySelectorAll('.summary-card');
            summaryCards.forEach((card, index) = > {
                card.style.opacity = '0';
                card.style.transform = 'translateY(30px)';
                card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';

                setTimeout(() = > {
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }, 300 + index * 100);
            });

            // 显示返回顶部按钮
            window.addEventListener('scroll', function() {
                const backToTopBtn = document.querySelector('button[onclick="scrollToTop() "]');
                if (window.pageYOffset > 300) {
                    backToTopBtn.style.opacity = '1';
                    backToTopBtn.style.pointerEvents = 'auto';
                }
                else {
                    backToTopBtn.style.opacity = '0';
                    backToTopBtn.style.pointerEvents = 'none';
                }
            });

            // 初始隐藏返回顶部按钮
            const backToTopBtn = document.querySelector('button[onclick="scrollToTop() "]');
            backToTopBtn.style.opacity = '0';
            backToTopBtn.style.transition = 'opacity 0.3s ease';
        });

        // 表格行点击高亮效果
        document.addEventListener('DOMContentLoaded', function() {
            const tableRows = document.querySelectorAll('tbody tr, table tr:not(:first-child)');

            tableRows.forEach(row = > {
                row.addEventListener('click', function() {
                    // 移除其他行的高亮
                    tableRows.forEach(r = > r.classList.remove('highlighted'));

                    // 添加当前行的高亮
                    this.classList.add('highlighted');

                    // 3秒后自动移除高亮
                    setTimeout(() = > {
                        this.classList.remove('highlighted');
                    }, 3000);
                });
            });
        });

        // 打印功能
        function printReport() {
            window.print();
        }

        // 导出功能提示
        function showExportOptions() {
            alert('💡 提示：您可以通过浏览器的"打印"功能将此报告保存为PDF文件\n\n或者使用Ctrl+P快捷键');
        }

        // 添加键盘快捷键支持
        document.addEventListener('keydown', function(e) {
            // Ctrl+P 打印
            if (e.ctrlKey&& e.key == = 'p') {
                e.preventDefault();
                printReport();
            }

            // Home键回到顶部
            if (e.key == = 'Home') {
                e.preventDefault();
                scrollToTop();
            }

            // F5刷新提示
            if (e.key == = 'F5') {
                e.preventDefault();
                if (confirm('🔄 确定要刷新页面吗？刷新后诊断数据将丢失。\n\n建议先保存此报告。')) {
                    location.reload();
                }
            }
        });

        // 复制表格数据功能
        function copyTableData(tableElement) {
            let csvContent = '';
            const rows = tableElement.querySelectorAll('tr');

            rows.forEach(row = > {
                const cells = row.querySelectorAll('td, th');
                const rowData = Array.from(cells).map(cell = >
                    '"' + cell.textContent.replace(/ "/g, '""') + '"'
                    ).join(',');
                csvContent += rowData + '\n';
            });

            navigator.clipboard.writeText(csvContent).then(() = > {
                // 显示复制成功提示
                showToast('📋 表格数据已复制到剪贴板');
            }).catch (() = > {
                // 降级方案
                const textArea = document.createElement('textarea');
                textArea.value = csvContent;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showToast('📋 表格数据已复制到剪贴板');
            });
        }

        // 显示Toast消息
        function showToast(message) {
            const toast = document.createElement('div');
            toast.textContent = message;
            toast.style.cssText = `
                position: fixed;
        top: 20px;
        right: 20px;
        background: linear - gradient(135deg, #27ae60, #2ecc71);
        color: white;
        padding: 15px 25px;
            border - radius: 8px;
            box - shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            z - index: 10000;
            font - weight: 600;
        transform: translateX(400px);
        transition: transform 0.3s ease;
            `;

                document.body.appendChild(toast);

            // 动画显示
            setTimeout(() = > {
                toast.style.transform = 'translateX(0)';
            }, 10);

            // 3秒后隐藏并移除
            setTimeout(() = > {
                toast.style.transform = 'translateX(400px)';
                setTimeout(() = > {
                    if (toast.parentNode) {
                        toast.parentNode.removeChild(toast);
                    }
                }, 300);
            }, 3000);
        }

        // 为表格添加右键菜单
        document.addEventListener('DOMContentLoaded', function() {
            const tables = document.querySelectorAll('table');

            tables.forEach(table = > {
                table.addEventListener('contextmenu', function(e) {
                    e.preventDefault();

                    // 移除已存在的右键菜单
                    const existingMenu = document.querySelector('.context-menu');
                    if (existingMenu) {
                        existingMenu.remove();
                    }

                    // 创建右键菜单
                    const contextMenu = document.createElement('div');
                    contextMenu.className = 'context-menu';
                    contextMenu.style.cssText = `
                        position: fixed;
                left: ${ e.clientX }px;
                top: ${ e.clientY }px;
                background: white;
                border: 1px solid #ddd;
                    border - radius: 8px;
                    box - shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
                    z - index: 10000;
                    min - width: 150px;
                overflow: hidden;
                    `;

                        const copyOption = document.createElement('div');
                    copyOption.textContent = '📋 复制表格数据';
                    copyOption.style.cssText = `
                        padding: 12px 16px;
                cursor: pointer;
                transition: background - color 0.2s ease;
                    font - size: 14px;
                    `;

                        copyOption.addEventListener('mouseenter', function() {
                        this.style.backgroundColor = '#f8f9fa';
                    });

                    copyOption.addEventListener('mouseleave', function() {
                        this.style.backgroundColor = 'white';
                    });

                    copyOption.addEventListener('click', function() {
                        copyTableData(table);
                        contextMenu.remove();
                    });

                    contextMenu.appendChild(copyOption);
                    document.body.appendChild(contextMenu);

                    // 点击其他地方时隐藏菜单
                    const hideMenu = function() {
                        if (contextMenu.parentNode) {
                            contextMenu.parentNode.removeChild(contextMenu);
                        }
                        document.removeEventListener('click', hideMenu);
                    };

                    setTimeout(() = > {
                        document.addEventListener('click', hideMenu);
                    }, 10);
                });
            });
        });
        < / script>

            <style>
            /* 高亮行样式 */
            tr.highlighted{
                background: linear - gradient(135deg, #fff3cd 0 %, #ffeaa7 100 %) !important;
                transform: scale(1.02);
                box - shadow: 0 4px 15px rgba(255, 193, 7, 0.3) !important;
                z - index: 10;
                position: relative;
        }

            /* 选中文本样式 */
            ::selection{
                background: linear - gradient(135deg, #667eea 0 %, #764ba2 100 %);
                color: white;
        }

            :: - moz - selection{
                background: linear - gradient(135deg, #667eea 0 %, #764ba2 100 %);
                color: white;
        }

            /* 打印样式 */
            @media print{
                body {
                    background: white !important;
                    font - size: 12px;
                }

                .container {
                    box - shadow: none !important;
                    border - radius: 0 !important;
                    padding: 20px !important;
                }

                h1, h2 {
                    color: #000 !important;
                    break - after: avoid;
                }

                table {
                    break - inside: avoid;
                    box - shadow: none !important;
                }

                tr {
                    break - inside: avoid;
                }

                .footer button {
                    display: none !important;
                }

                .summary - grid {
                    break - inside: avoid;
                }
        }
            < / style>
            < / body>
            < / html> )";

                
            // 写入UTF-8字节流（无BOM）
            file.write(html_content.c_str(), html_content.length());
        file.close();

        return DiagnosticResult(DiagnosticErrorCode::SUCCESS,
            "Enhanced HTML report generated successfully (UTF-8 without BOM): " + output_path);
    }
};


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