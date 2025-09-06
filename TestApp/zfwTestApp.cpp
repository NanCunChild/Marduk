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

// UTF-8 ת UTF-16 �ĸ�������
std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// UTF-16 ת UTF-8 �ĸ�������
std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// �����뵽���ַ�����ת������
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

// UTF-16 �汾�Ľ����ӡ����
void printLoginResult(const LoginResult& result) {
    std::wcout << L"\n=== ��¼��� ===\n";
    std::wcout << L"�������: " << static_cast<int>(result.error_code)
        << L" (" << errorCodeToWString(result.error_code) << L")\n";

    if (result.isSuccess()) {
        std::wcout << L"״̬: �ɹ�\n";
        std::wcout << L"��Ϣ: " << utf8_to_wstring(result.error_message) << L"\n";

        // ��ӡ�û���Ϣ
        const UserInfo& userInfo = result.user_info;
        std::wcout << L"\n=== �û���Ϣ ===\n";
        std::wcout << L"--- �û���� ---\n";
        std::wcout << L"�û���: " << userInfo.username << L"\n";
        std::wcout << L"��ʵ����: " << utf8_to_wstring(userInfo.realname) << L"\n";
        std::wcout << L"�˻�״̬: " << utf8_to_wstring(userInfo.user_status) << L"\n";
        std::wcout << L"����Ǯ��: " << userInfo.wallet << L" Ԫ\n";

        std::wcout << L"\n--- �ײ���� ---\n";
        std::wcout << L"���ײ���: " << userInfo.plan_num << L"\n";
        std::wcout << L"���������ײ�: " << (userInfo.telecom_plan ? L"��" : L"��") << L"\n";
        std::wcout << L"������ͨ�ײ�: " << (userInfo.unicom_plan ? L"��" : L"��") << L"\n";
        std::wcout << L"�����ƶ��ײ�: " << (userInfo.mobile_plan ? L"��" : L"��") << L"\n";

        std::wcout << L"\n--- IP��� ---\n";
        std::wcout << L"���IP����: " << userInfo.ip_free_count << L"\n";
        for (const auto& ip : userInfo.ip_free_list) {
            std::wcout << L"  - " << utf8_to_wstring(ip) << L"\n";
        }
        std::wcout << L"����IP����: " << userInfo.ip_pay_count << L"\n";
        for (const auto& ip : userInfo.ip_pay_list) {
            std::wcout << L"  - " << utf8_to_wstring(ip) << L"\n";
        }
    }
    else {
        std::wcout << L"״̬: ʧ��\n";
        std::wcout << L"������Ϣ: " << utf8_to_wstring(result.error_message) << L"\n";

        // ���ݴ��������ṩ����
        switch (result.error_code) {
        case ZfwErrorCode::LOGIC_USERNAME_PASSWORD_ERROR:
            std::wcout << L"����: �����û��������롣\n";
            break;
        case ZfwErrorCode::CAPTCHA_VALIDATION_FAILED:
        case ZfwErrorCode::CAPTCHA_INVALID_LENGTH:
            std::wcout << L"����: ��֤��ʶ��ʧ�ܣ������ԡ�\n";
            break;
        case ZfwErrorCode::NETWORK_CPR_ERROR:
        case ZfwErrorCode::NETWORK_GET_LOGIN_PAGE_FAILED:
            std::wcout << L"����: �����������ӡ�\n";
            break;
        case ZfwErrorCode::SYSTEM_MODEL_NOT_LOADED:
            std::wcout << L"����: ȷ�� crnn_model.onnx �ļ������ڵ�ǰĿ¼��\n";
            break;
        default:
            std::wcout << L"����: ���������������顣\n";
            break;
        }
    }
    std::wcout << L"========================\n";
}

// ʹ�� wmain ��Ϊ���ַ���ڵ�
int wmain(int argc, wchar_t* argv[]) {
    // ���ÿ���̨ΪUTF-16ģʽ
    int result = _setmode(_fileno(stdout), _O_U16TEXT);
    if (result == -1) {
        std::wcout << L"����: �޷����ÿ���̨ΪUTF-16ģʽ\n";
    }

    std::wcout << L"=== ���� ZfwInteractionDll: ������¼���� ===\n";

    // ���ģ���ļ��Ƿ����
    std::wstring model_path = L"crnn_model.onnx";
    if (!std::filesystem::exists(model_path)) {
        std::wcout << L"����: ģ���ļ� 'crnn_model.onnx' δ�ҵ�!\n";
        std::wcout << L"��ȷ��ONNXģ���ļ��ڵ�ǰĿ¼�С�\n";
        std::wcout << L"��Enter���˳�...";
        std::wcin.get();
        return 1;
    }

    try {
        // ��ʼ�� ZfwManager
        ZfwManager zfw(model_path);

        // �û����루ʹ�ÿ��ַ���
        std::wstring w_username, w_password;
        std::wcout << L"�����û���: ";
        std::getline(std::wcin, w_username);
        std::wcout << L"��������: ";
        std::getline(std::wcin, w_password);

        // ת��ΪUTF-8��DLLʹ��
        std::string username = wstring_to_utf8(w_username);
        std::string password = wstring_to_utf8(w_password);

        std::wcout << L"\n���ڳ������û� " << w_username << L" ��ݵ�¼...\n";

        // ִ�е�¼
        LoginResult result = zfw.login(username, password);

        // ��ӡ���
        printLoginResult(result);

        // ����ɹ������Խ�����������
        if (result.isSuccess()) {
            std::wcout << L"\n��¼�ɹ������ڿ���ִ������������\n";

            // ʾ������ȡ CSRF Token �� Public Key
            std::string csrf = zfw.getCsrfToken();
            std::string pubkey = zfw.getPublicKey();
            std::wcout << L"CSRF Token: " << utf8_to_wstring(csrf.substr(0, 20)) << L"...\n";
            std::wcout << L"��Կ����: " << pubkey.length() << L" �ַ�\n";
        }
    }
    catch (const std::exception& e) {
        std::wcout << L"�����쳣: " << utf8_to_wstring(e.what()) << L"\n";
    }
    catch (...) {
        std::wcout << L"����δ֪�쳣!\n";
    }

    std::wcout << L"\n��Enter���˳�...";
    std::wcin.get();
    return 0;
}