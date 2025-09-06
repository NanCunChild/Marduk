#pragma once

#ifdef ZFWINTERACTIONDLL_EXPORTS
#define ZFW_API __declspec(dllexport)
#else
#define ZFW_API __declspec(dllimport)
#endif

#include <string>
#include <vector>

enum class ZfwErrorCode : int {
    SUCCESS = 0,

    // 网络错误 (1000-1999)
    NETWORK_GET_LOGIN_PAGE_FAILED = 1001,
    NETWORK_CPR_ERROR = 1002,
    NETWORK_GET_CAPTCHA_FAILED = 1003,
    NETWORK_LOGIN_REQUEST_FAILED = 1004,
    NETWORK_GET_DASHBOARD_FAILED = 1005,

    // 验证码错误 (4000-4999)
    CAPTCHA_INVALID_LENGTH = 4001,
    CAPTCHA_VALIDATION_FAILED = 4002,
    CAPTCHA_RECOGNITION_FAILED = 4003,

    // 逻辑错误 (5000-5999)
    LOGIC_USERNAME_PASSWORD_ERROR = 5001,
    LOGIC_LOGIN_TIMEOUT = 5002,
    LOGIC_PASSWORD_ENCRYPTION_FAILED = 5003,
    LOGIC_CSRF_TOKEN_MISSING = 5004,
    LOGIC_PUBLIC_KEY_MISSING = 5005,
    LOGIC_UNEXPECTED_RESPONSE = 5999,

    // 系统错误 (9000-9999)
    SYSTEM_MODEL_NOT_LOADED = 9001,
    SYSTEM_UNKNOWN_ERROR = 9999
};

struct UserInfo {
    std::string status;
    std::string message;
    int error_code = 0;

    std::string username;
    std::string realname;
    std::string user_status;
    double wallet = 0.0;

    int plan_num = 0;
    bool unicom_plan = false;
    bool telecom_plan = false;
    bool mobile_plan = false;

    int ip_pay_count = 0;
    int ip_free_count = 0;
    std::vector<std::string> ip_pay_list;
    std::vector<std::string> ip_free_list;
};

struct LoginResult {
    ZfwErrorCode error_code;
    std::string error_message;
    UserInfo user_info;

    LoginResult(ZfwErrorCode code = ZfwErrorCode::SUCCESS, const std::string& message = "")
        : error_code(code), error_message(message) {
    }

    bool isSuccess() const { return error_code == ZfwErrorCode::SUCCESS; }
};

class ZFW_API ZfwManager {
public:
    ZfwManager(const std::wstring& model_path);
    ~ZfwManager();
    /*UserInfo login(const std::string& username, const std::string& password);*/
    LoginResult login(const std::string& username, const std::string& password);
    std::string getCsrfToken() const;
    std::string getPublicKey() const;
private:
    class ZfwManagerImpl;
    ZfwManagerImpl* impl;
};