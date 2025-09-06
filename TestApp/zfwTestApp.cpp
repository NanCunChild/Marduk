#include <iostream>
#include <Windows.h>
#include <locale>
#include <fcntl.h>
#include <filesystem>
#include <shlobj.h>
#include <fstream>
#include <io.h>
#include "../ZfwInteractionDll/ZfwManager.h"
#pragma comment(lib, "shell32.lib")

// UTF-8 转 UTF-16 的辅助函数
std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// UTF-16 转 UTF-8 的辅助函数
std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// 错误码到宽字符串的转换函数
std::wstring errorCodeToWString(ZfwErrorCode code) {
    switch (code) {
    case ZfwErrorCode::SUCCESS:
        return L"SUCCESS";
    case ZfwErrorCode::NETWORK_GET_LOGIN_PAGE_FAILED:
        return L"NETWORK_GET_LOGIN_PAGE_FAILED";
    case ZfwErrorCode::NETWORK_CPR_ERROR:
        return L"NETWORK_CPR_ERROR";
    case ZfwErrorCode::NETWORK_GET_CAPTCHA_FAILED:
        return L"NETWORK_GET_CAPTCHA_FAILED";
    case ZfwErrorCode::NETWORK_LOGIN_REQUEST_FAILED:
        return L"NETWORK_LOGIN_REQUEST_FAILED";
    case ZfwErrorCode::NETWORK_GET_DASHBOARD_FAILED:
        return L"NETWORK_GET_DASHBOARD_FAILED";
    case ZfwErrorCode::CAPTCHA_INVALID_LENGTH:
        return L"CAPTCHA_INVALID_LENGTH";
    case ZfwErrorCode::CAPTCHA_VALIDATION_FAILED:
        return L"CAPTCHA_VALIDATION_FAILED";
    case ZfwErrorCode::CAPTCHA_RECOGNITION_FAILED:
        return L"CAPTCHA_RECOGNITION_FAILED";
    case ZfwErrorCode::LOGIC_USERNAME_PASSWORD_ERROR:
        return L"LOGIC_USERNAME_PASSWORD_ERROR";
    case ZfwErrorCode::LOGIC_LOGIN_TIMEOUT:
        return L"LOGIC_LOGIN_TIMEOUT";
    case ZfwErrorCode::LOGIC_PASSWORD_ENCRYPTION_FAILED:
        return L"LOGIC_PASSWORD_ENCRYPTION_FAILED";
    case ZfwErrorCode::LOGIC_CSRF_TOKEN_MISSING:
        return L"LOGIC_CSRF_TOKEN_MISSING";
    case ZfwErrorCode::LOGIC_PUBLIC_KEY_MISSING:
        return L"LOGIC_PUBLIC_KEY_MISSING";
    case ZfwErrorCode::LOGIC_UNEXPECTED_RESPONSE:
        return L"LOGIC_UNEXPECTED_RESPONSE";
    case ZfwErrorCode::SYSTEM_MODEL_NOT_LOADED:
        return L"SYSTEM_MODEL_NOT_LOADED";
    case ZfwErrorCode::SYSTEM_UNKNOWN_ERROR:
        return L"SYSTEM_UNKNOWN_ERROR";
    default:
        return L"UNKNOWN_ERROR_CODE";
    }
}

// UTF-16 版本的结果打印函数
void printLoginResult(const LoginResult& result) {
    std::wcout << L"\n=== 登录结果 ===\n";
    std::wcout << L"错误代码: " << static_cast<int>(result.error_code)
        << L" (" << errorCodeToWString(result.error_code) << L")\n";

    if (result.isSuccess()) {
        std::wcout << L"状态: 成功\n";
        std::wcout << L"消息: " << utf8_to_wstring(result.error_message) << L"\n";

        // 打印用户信息
        const UserInfo& userInfo = result.user_info;
        std::wcout << L"\n=== 用户信息 ===\n";
        std::wcout << L"--- 用户面板 ---\n";
        std::wcout << L"用户名: " << userInfo.username << L"\n";
        std::wcout << L"真实姓名: " << utf8_to_wstring(userInfo.realname) << L"\n";
        std::wcout << L"账户状态: " << utf8_to_wstring(userInfo.user_status) << L"\n";
        std::wcout << L"电子钱包: " << userInfo.wallet << L" 元\n";

        std::wcout << L"\n--- 套餐面板 ---\n";
        std::wcout << L"总套餐数: " << userInfo.plan_num << L"\n";
        std::wcout << L"包含电信套餐: " << (userInfo.telecom_plan ? L"是" : L"否") << L"\n";
        std::wcout << L"包含联通套餐: " << (userInfo.unicom_plan ? L"是" : L"否") << L"\n";
        std::wcout << L"包含移动套餐: " << (userInfo.mobile_plan ? L"是" : L"否") << L"\n";

        std::wcout << L"\n--- IP面板 ---\n";
        std::wcout << L"免费IP数量: " << userInfo.ip_free_count << L"\n";
        for (const auto& ip : userInfo.ip_free_list) {
            std::wcout << L"  - " << utf8_to_wstring(ip) << L"\n";
        }
        std::wcout << L"付费IP数量: " << userInfo.ip_pay_count << L"\n";
        for (const auto& ip : userInfo.ip_pay_list) {
            std::wcout << L"  - " << utf8_to_wstring(ip) << L"\n";
        }
    }
    else {
        std::wcout << L"状态: 失败\n";
        std::wcout << L"错误消息: " << utf8_to_wstring(result.error_message) << L"\n";

        // 根据错误类型提供建议
        switch (result.error_code) {
        case ZfwErrorCode::LOGIC_USERNAME_PASSWORD_ERROR:
            std::wcout << L"建议: 请检查用户名和密码。\n";
            break;
        case ZfwErrorCode::CAPTCHA_VALIDATION_FAILED:
        case ZfwErrorCode::CAPTCHA_INVALID_LENGTH:
            std::wcout << L"建议: 验证码识别失败，请重试。\n";
            break;
        case ZfwErrorCode::NETWORK_CPR_ERROR:
        case ZfwErrorCode::NETWORK_GET_LOGIN_PAGE_FAILED:
            std::wcout << L"建议: 请检查网络连接。\n";
            break;
        case ZfwErrorCode::SYSTEM_MODEL_NOT_LOADED:
            std::wcout << L"建议: 确保 crnn_model.onnx 文件存在于当前目录。\n";
            break;
        default:
            std::wcout << L"建议: 请检查上述错误详情。\n";
            break;
        }
    }
    std::wcout << L"========================\n";
}

// 使用 wmain 作为宽字符入口点
int wmain(int argc, wchar_t* argv[]) {
    // 设置控制台为UTF-16模式
    int result = _setmode(_fileno(stdout), _O_U16TEXT);
    if (result == -1) {
        std::wcout << L"警告: 无法设置控制台为UTF-16模式\n";
    }

    std::wcout << L"=== 测试 ZfwInteractionDll: 完整登录流程 ===\n";

    // 检查模型文件是否存在
    std::wstring model_path = L"crnn_model.onnx";
    if (!std::filesystem::exists(model_path)) {
        std::wcout << L"错误: 模型文件 'crnn_model.onnx' 未找到!\n";
        std::wcout << L"请确保ONNX模型文件在当前目录中。\n";
        std::wcout << L"按Enter键退出...";
        std::wcin.get();
        return 1;
    }

    try {
        // 初始化 ZfwManager
        ZfwManager zfw(model_path);

        // 用户输入（使用宽字符）
        std::wstring w_username, w_password;
        std::wcout << L"输入用户名: ";
        std::getline(std::wcin, w_username);
        std::wcout << L"输入密码: ";
        std::getline(std::wcin, w_password);

        // 转换为UTF-8供DLL使用
        std::string username = wstring_to_utf8(w_username);
        std::string password = wstring_to_utf8(w_password);

        std::wcout << L"\n正在尝试以用户 " << w_username << L" 身份登录...\n";

        // 执行登录
        LoginResult result = zfw.login(username, password);

        // 打印结果
        printLoginResult(result);

        // 如果成功，可以进行其他操作
        if (result.isSuccess()) {
            std::wcout << L"\n登录成功！现在可以执行其他操作。\n";

            // 示例：获取 CSRF Token 和 Public Key
            std::string csrf = zfw.getCsrfToken();
            std::string pubkey = zfw.getPublicKey();
            std::wcout << L"CSRF Token: " << utf8_to_wstring(csrf.substr(0, 20)) << L"...\n";
            std::wcout << L"公钥长度: " << pubkey.length() << L" 字符\n";
        }
    }
    catch (const std::exception& e) {
        std::wcout << L"捕获异常: " << utf8_to_wstring(e.what()) << L"\n";
    }
    catch (...) {
        std::wcout << L"捕获未知异常!\n";
    }

    std::wcout << L"\n按Enter键退出...";
    std::wcin.get();
    return 0;
}