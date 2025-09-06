#pragma once

#include "pch.h"
#include "ZfwManager.h"

#pragma warning(push, 0)

#include <cpr/cpr.h>
#include <gumbo.h>
#include <nlohmann/json.hpp>
#include <onnxruntime_cxx_api.h>
#include <opencv2/opencv.hpp>

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>

#pragma warning(pop)

#include <regex>
#include <curl/curl.h>

#include <iostream>
#include <exception>
#include <stdexcept>
#include <vector>
#include <Windows.h>


static bool has_class(GumboNode* node, const std::string& className) {
    GumboAttribute* class_attr = gumbo_get_attribute(&node->v.element.attributes, "class");
    if (!class_attr) return false;

    std::string classes = " " + std::string(class_attr->value) + " ";
    return classes.find(" " + className + " ") != std::string::npos;
}

static GumboNode* find_node_by_tag_and_class(GumboNode* node, GumboTag tag, const std::string& className) {
    if (node->type != GUMBO_NODE_ELEMENT) {
        return nullptr;
    }

    if (node->v.element.tag == tag && has_class(node, className)) {
        return node;
    }

    GumboVector* children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        GumboNode* found = find_node_by_tag_and_class(static_cast<GumboNode*>(children->data[i]), tag, className);
        if (found) return found;
    }
    return nullptr;
}

// --- ADD THIS NEW HELPER FUNCTION ---
/**
 * @brief (NEW & ROBUST) Recursively searches for the first element with a specific ID.
 * @param node The node to start the search from.
 * @param id The ID to search for.
 * @return A pointer to the found GumboNode, or nullptr if not found.
 */
static GumboNode* find_first_by_id(GumboNode* node, const std::string& id) {
    if (node->type != GUMBO_NODE_ELEMENT) {
        return nullptr;
    }

    GumboAttribute* id_attr = gumbo_get_attribute(&node->v.element.attributes, "id");
    if (id_attr && std::string(id_attr->value) == id) {
        return node;
    }

    GumboVector* children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        GumboNode* found = find_first_by_id(static_cast<GumboNode*>(children->data[i]), id);
        if (found) return found;
    }

    return nullptr;
}

/**
 * @brief (新) 递归搜索并返回第一个匹配特定标签的节点。
 * @param node 起始搜索节点。
 * @param tag 要查找的GumboTag。
 * @return 找到的第一个GumboNode*，如果没找到则返回nullptr。
 */
static GumboNode* find_first_by_tag(GumboNode* node, GumboTag tag) {
    if (node->type != GUMBO_NODE_ELEMENT) {
        return nullptr;
    }
    if (node->v.element.tag == tag) {
        return node;
    }
    GumboVector* children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        GumboNode* found = find_first_by_tag(static_cast<GumboNode*>(children->data[i]), tag);
        if (found) return found;
    }
    return nullptr;
}

/**
 * @brief (新) 递归搜索所有包含特定CSS类名的节点。
 * @param node 起始搜索节点。
 * @param className 要查找的CSS类名。
 * @param results 用于存储结果的vector引用。
 */
static void find_all_nodes_with_class(GumboNode* node, const std::string& className, std::vector<GumboNode*>& results) {
    if (node->type != GUMBO_NODE_ELEMENT) {
        return;
    }
    if (has_class(node, className)) {
        results.push_back(node);
    }
    GumboVector* children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        find_all_nodes_with_class(static_cast<GumboNode*>(children->data[i]), className, results);
    }
}

// 辅助函数：获取节点的纯文本内容
static std::string get_node_text(GumboNode* node) {
    if (node->type == GUMBO_NODE_TEXT) {
        return std::string(node->v.text.text);
    }
    if (node->type == GUMBO_NODE_ELEMENT && node->v.element.children.length > 0) {
        std::string text = "";
        GumboVector* children = &node->v.element.children;
        for (unsigned int i = 0; i < children->length; ++i) {
            text += get_node_text(static_cast<GumboNode*>(children->data[i]));
        }
        return text;
    }
    return "";
}

// 辅助函数：获取紧邻的下一个文本节点内容（模拟 .next_sibling）
static std::string get_direct_text_sibling(GumboNode* node) {
    GumboNode* parent = node->parent;
    if (!parent || parent->type != GUMBO_NODE_ELEMENT) return "";

    GumboVector* siblings = &parent->v.element.children;
    for (unsigned int i = 0; i < siblings->length; ++i) {
        if (static_cast<GumboNode*>(siblings->data[i]) == node) {
            if (i + 1 < siblings->length) {
                GumboNode* next_sibling = static_cast<GumboNode*>(siblings->data[i + 1]);
                if (next_sibling->type == GUMBO_NODE_TEXT || next_sibling->type == GUMBO_NODE_WHITESPACE) {
                    // C++17 string_view would be more efficient, but string is fine.
                    std::string text = next_sibling->v.text.text;
                    // trim whitespace
                    text.erase(0, text.find_first_not_of(" \t\n\r"));
                    text.erase(text.find_last_not_of(" \t\n\r") + 1);
                    return text;
                }
            }
        }
    }
    return "";
}

// 辅助函数：递归搜索所有匹配特定 tag 的节点（模拟 .find_all）
static void find_all_nodes_by_tag(GumboNode* node, GumboTag tag, std::vector<GumboNode*>& results) {
    if (node->type != GUMBO_NODE_ELEMENT) {
        return;
    }
    if (node->v.element.tag == tag) {
        results.push_back(node);
    }
    GumboVector* children = &node->v.element.children;
    //get_node_text(node);
    for (unsigned int i = 0; i < children->length; ++i) {
        find_all_nodes_by_tag(static_cast<GumboNode*>(children->data[i]), tag, results);
    }
}

// --- Gumbo 解析辅助函数 ---
static void search_for_tags(GumboNode* node, std::string& csrfToken, std::string& publicKey) {
    if (node->type != GUMBO_NODE_ELEMENT) { return; }
    if (node->v.element.tag == GUMBO_TAG_META) {
        GumboAttribute* name_attr = gumbo_get_attribute(&node->v.element.attributes, "name");
        if (name_attr && std::string(name_attr->value) == "csrf-token") {
            GumboAttribute* content_attr = gumbo_get_attribute(&node->v.element.attributes, "content");
            if (content_attr) { csrfToken = content_attr->value; }
        }
    }
    if (node->v.element.tag == GUMBO_TAG_INPUT) {
        GumboAttribute* id_attr = gumbo_get_attribute(&node->v.element.attributes, "id");
        if (id_attr && std::string(id_attr->value) == "public") {
            GumboAttribute* value_attr = gumbo_get_attribute(&node->v.element.attributes, "value");
            if (value_attr) { publicKey = value_attr->value; }
        }
    }
    GumboVector* children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        if (!csrfToken.empty() && !publicKey.empty()) { break; }
        search_for_tags(static_cast<GumboNode*>(children->data[i]), csrfToken, publicKey);
    }
}

class ZfwManager::ZfwManagerImpl {
public:
    cpr::Session session;
    std::string csrf_token;
    std::string public_key;

    Ort::Env env;
    Ort::Session ort_session{ nullptr };
    std::vector<const char*> input_node_names{ "input" };
    std::vector<const char*> output_node_names{ "output" };

    ZfwManagerImpl(const std::wstring& model_path)
        :env(ORT_LOGGING_LEVEL_WARNING, "ZfwManagerImpl") {

        session.SetHeader(cpr::Header{
            {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"},
            {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
            {"Accept-Language", "zh-CN,zh;q=0.9"}
            });
        session.SetVerifySsl(cpr::VerifySsl(false));
        session.SetTimeout(15000);
        session.SetProxies({});
        //session.SetOption(cpr::Verbose{ true });
        session.SetRedirect(cpr::Redirect{ 0L });

        Ort::SessionOptions session_options;
        try {
            OrtCUDAProviderOptions cuda_options{};
            session_options.AppendExecutionProvider_CUDA(cuda_options);
        }
        catch (...) {
            std::wcerr << "CUDA provider is not available. Falling back to CPU." << std::endl;
        }
        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        try {
            ort_session = Ort::Session(env, model_path.c_str(), session_options);
        }
        catch (const Ort::Exception& e) {
            std::wcerr << "Failed to load ONNX model: " << e.what() << std::endl;
        }
    }

    // [Optimized Parsing Logic]
    void parseUserInfo(GumboNode* root, UserInfo& userInfo) {
        GumboNode* user_panel = find_node_by_tag_and_class(root, GUMBO_TAG_DIV, "query-user");
        if (!user_panel) {
            std::wcout << "[Debug] User panel with class 'query-user' NOT FOUND.\n";
            return;
        }
        //std::wcout << "[Debug] User panel found.\n";

        std::vector<GumboNode*> items;
        find_all_nodes_with_class(user_panel, "list-group-item", items);

        for (GumboNode* item : items) {
            if (item->type != GUMBO_NODE_ELEMENT) continue;

            GumboNode* label_node = find_first_by_tag(item, GUMBO_TAG_LABEL);
            if (!label_node) continue;

            std::string label_text = get_node_text(label_node);

            // --- 侦查代码 ---
            //std::wcout << u8"[侦查] 正在处理 Label: '" << label_text << "'" << std::endl;

            if (label_text == u8"状态") {
                //std::wcout << u8"[侦查] '状态' 标签匹配成功! 正在查找 <a> 标签..." << std::endl;
                GumboNode* status_link = find_first_by_tag(item, GUMBO_TAG_A);
                if (status_link) {
                    userInfo.user_status = get_node_text(status_link);
                    //std::wcout << u8"[侦查] 成功找到 <a> 标签, 状态为: '" << userInfo.user_status << "'" << std::endl;
                }
                else {
                    std::wcout << u8"[Debug] 警告: 未能在 '状态' 列表项中找到 <a> 标签!" << std::endl;
                }
                continue;
            }

            std::string full_text = get_node_text(item);

            size_t pos = full_text.find(label_text);
            if (pos != std::string::npos) {
                full_text.erase(pos, label_text.length());
            }

            const std::string& whitespace = " \t\n\r\f\v";
            size_t first = full_text.find_first_not_of(whitespace);
            if (std::string::npos == first) {
                full_text = "";
            }
            else {
                size_t last = full_text.find_last_not_of(whitespace);
                full_text = full_text.substr(first, (last - first + 1));
            }

            if (label_text == u8"用户名") {
                userInfo.username = full_text;
            }
            else if (label_text == u8"姓名") {
                userInfo.realname = full_text;
            }
            else if (label_text == u8"电子钱包") {
                try {
                    userInfo.wallet = std::stod(full_text);
                }
                catch (...) {
                    userInfo.wallet = 0.0;
                }
            }
        }
    }

    void parsePlanInfo(GumboNode* root, UserInfo& userInfo) {
        // Use the new, robust finder to locate the panel by its unique ID
        GumboNode* plan_panel = find_first_by_id(root, "w3");

        if (!plan_panel) {
            std::wcout << "[Debug] Product info panel with id 'w3' NOT FOUND.\n";
            return;
        }
        //std::wcout << "[Debug] Product info panel with id 'w3' FOUND.\n";

        // 1. Extract total plan count from the summary div
        GumboNode* summary_div = find_node_by_tag_and_class(plan_panel, GUMBO_TAG_DIV, "summary");
        if (summary_div) {
            std::string summary_text = get_node_text(summary_div);
            std::smatch match;
            // Regex to find the number between "共" and "条"
            if (std::regex_search(summary_text, match, std::regex(u8"共.*?(\\d+).*?条"))) {
                try {
                    userInfo.plan_num = std::stoi(match[1].str());
                    //std::wcout << "[Debug] Plan count found from summary: " << userInfo.plan_num << "\n";
                }
                catch (...) {
                    userInfo.plan_num = 0;
                }
            }
        }
        else {
            std::wcout << "[Debug] Summary div not found, plan count will be 0.\n";
            userInfo.plan_num = 0;
        }

        // 2. Iterate through table rows to determine plan types
        GumboNode* plan_table = find_node_by_tag_and_class(plan_panel, GUMBO_TAG_TABLE, "kv-grid-table");
        if (plan_table) {
            std::vector<GumboNode*> rows;
            find_all_nodes_by_tag(plan_table, GUMBO_TAG_TR, rows);

            for (GumboNode* row : rows) {
                std::string row_text = get_node_text(row);
                if (row_text.find(u8"联通") != std::string::npos) userInfo.unicom_plan = true;
                if (row_text.find(u8"电信") != std::string::npos) userInfo.telecom_plan = true;
                if (row_text.find(u8"移动") != std::string::npos) userInfo.mobile_plan = true;
            }
        }
        else {
            //std::wcout << "[Debug] Plan table with class 'kv-grid-table' NOT FOUND in plan panel.\n";
        }
    }


    bool is_valid_ip(const std::string& ip_address) {
        static const std::regex pattern(R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
        return std::regex_match(ip_address, pattern);
    }

    void parseIpInfo(GumboNode* root, UserInfo& userInfo) {
        GumboNode* ip_table = find_node_by_tag_and_class(root, GUMBO_TAG_TABLE, "table-striped");
        if (!ip_table) {
            //std::wcout << "[Debug] IP table with class 'table-striped' NOT FOUND.\n";
            return;
        }
        //std::wcout << "[Debug] IP table found.\n";

        std::vector<GumboNode*> rows;
        find_all_nodes_by_tag(ip_table, GUMBO_TAG_TR, rows);

        for (GumboNode* row : rows) {
            std::vector<GumboNode*> cells;
            find_all_nodes_by_tag(row, GUMBO_TAG_TD, cells);
            if (cells.empty()) continue;

            std::string ip_address = "";
            bool is_pay_ip = false;

            for (GumboNode* cell : cells) {
                std::string cell_text = get_node_text(cell);
                if (is_valid_ip(cell_text)) {
                    ip_address = cell_text;
                }
                if (cell_text.find("电信") != std::string::npos || cell_text.find("联通") != std::string::npos || cell_text.find("移动") != std::string::npos) {
                    is_pay_ip = true;
                }
            }

            if (!ip_address.empty()) {
                if (is_pay_ip) {
                    userInfo.ip_pay_list.push_back(ip_address);
                }
                else {
                    userInfo.ip_free_list.push_back(ip_address);
                }
            }
        }
        userInfo.ip_pay_count = static_cast<int>(userInfo.ip_pay_list.size());
        userInfo.ip_free_count = static_cast<int>(userInfo.ip_free_list.size());
    }

    void parseDashboard(const std::string& html, UserInfo& userInfo) {
        //std::wcout << "[Debug] Saving received HTML to dashboard.html...\n";
        std::ofstream out_file("dashboard.html");
        if (out_file) {
            out_file << html;
            out_file.close();
        }

        GumboOutput* output = gumbo_parse(html.c_str());
        if (!output) return;

        parseUserInfo(output->root, userInfo);
        parsePlanInfo(output->root, userInfo);
        parseIpInfo(output->root, userInfo);

        gumbo_destroy_output(&kGumboDefaultOptions, output);
    }

    bool fetchLoginPageInfo() {
        try
        {
            session.SetUrl(cpr::Url{ "https://zfw.xidian.edu.cn/" });
            cpr::Response r = session.Get();
            if (r.status_code != 200) { return false; }

            GumboOutput* output = gumbo_parse(r.text.c_str());
            if (!output) { return false; }

            search_for_tags(output->root, this->csrf_token, this->public_key);
            gumbo_destroy_output(&kGumboDefaultOptions, output);

            return !this->csrf_token.empty() && !this->public_key.empty();
        } catch(const cpr::Error& e){
            std::wcerr << L"Login Fetch Exception: " << std::wstring(e.message.begin(), e.message.end()) << std::endl;
            return false;
		}
    }

    std::string encryptPassword(const std::string& password) {
        using namespace CryptoPP;
        try {
            // 1. 从 PEM 字符串中提取 Base64 部分
            std::string pem = this->public_key;
            pem = std::regex_replace(pem, std::regex("-----BEGIN PUBLIC KEY-----"), "");
            pem = std::regex_replace(pem, std::regex("-----END PUBLIC KEY-----"), "");
            pem = std::regex_replace(pem, std::regex("\\s"), ""); // 移除所有空白字符

            // 2. Base64 解码，加载密钥
            RSA::PublicKey publicKey;
            StringSource ss(pem, true, new Base64Decoder);
            publicKey.Load(ss);

            // 3. 执行加密
            RSAES_PKCS1v15_Encryptor encryptor(publicKey);
            AutoSeededRandomPool rng;
            std::string encrypted;
            StringSource(password, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encrypted)));

            // 4. 将加密结果进行 Base64 编码
            std::string base64_encrypted;
            StringSource(encrypted, true, new Base64Encoder(new StringSink(base64_encrypted), false));

            return base64_encrypted;
        }
        catch (const CryptoPP::Exception& e) {
            std::wcerr << "Crypto++ Exception: " << e.what() << std::endl;
            return "";
        }
    }

    std::string recognizeCaptcha(const cpr::Response& r) {
        if (ort_session == nullptr) return "";
        std::vector<uchar> img_data(r.text.begin(), r.text.end());
        cv::Mat image = cv::imdecode(img_data, cv::IMREAD_GRAYSCALE);
        if (image.empty()) return "";
        cv::Mat resized_image;
        cv::resize(image, resized_image, cv::Size(90, 34));
        resized_image.convertTo(resized_image, CV_32F);
        resized_image = (resized_image - 127.5) / 127.5;

        std::vector<int64_t> input_shape = { 1, 1, 34, 90 };
        size_t input_tensor_size = 34 * 90;

        Ort::MemoryInfo memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(memory_info, (float*)resized_image.data, input_tensor_size, input_shape.data(), input_shape.size());

        auto output_tensors = ort_session.Run(Ort::RunOptions{ nullptr }, input_node_names.data(), &input_tensor, 1, output_node_names.data(), 1);

        const float* floatarr = output_tensors[0].GetTensorData<const float>();
        auto output_shape = output_tensors[0].GetTensorTypeAndShapeInfo().GetShape();
        auto width = output_shape[0];
        auto num_classes = output_shape[2];
        std::string result = "";
        int64_t last_index = 0;
        for (int64_t t = 0; t < width; ++t) {
            int64_t max_index = 0;
            float max_prob = -1.0f;
            for (int c = 0; c < num_classes; ++c) {
                if (floatarr[t * num_classes + c] > max_prob) {
                    max_prob = floatarr[t * num_classes + c];
                    max_index = c;
                }
            }
            if (max_index != 0 && max_index != last_index) {
                result += std::to_string(max_index - 1);
            }
            last_index = max_index;
        }
        //std::wcout << "[Debug] captcha recognized:" << result << "\n";
        return result;
    }

    LoginResult doLogin(const std::string& username, const std::string& password) {
        UserInfo result;

        std::string initial_csrf_token;
        std::string captcha_code;
        std::string encrypted_password;
        bool login_succeeded = false;

        for (int attempt = 0; attempt < 2; ++attempt) {

            if (!fetchLoginPageInfo()) {
                return LoginResult(ZfwErrorCode::NETWORK_GET_LOGIN_PAGE_FAILED,
                    "Failed to get login page info (CSRF/Public Key).");
            }

            initial_csrf_token = this->csrf_token;

            session.SetUrl(cpr::Url{ "https://zfw.xidian.edu.cn/site/captcha" });
            cpr::Response captcha_r;
            try {
                captcha_r = session.Get();
            }
            catch (const cpr::Error& e) {
                return LoginResult(ZfwErrorCode::NETWORK_CPR_ERROR,
                    "CPR library error during captcha request:" + std::string(e.message));
            }

            if (captcha_r.status_code != 200) {
                return LoginResult(ZfwErrorCode::NETWORK_GET_CAPTCHA_FAILED,
                    "Failed to get captcha, status code: " + std::to_string(captcha_r.status_code));
            }

            // 其实不太可能出现，验证码从训练开始就要求输出4位
            captcha_code = recognizeCaptcha(captcha_r);
            if (captcha_code.length() != 4) {
                return LoginResult(ZfwErrorCode::CAPTCHA_INVALID_LENGTH,
                    "Invalid captcha length: " + std::to_string(captcha_code.length()));
            }

            // 这个也不太可能出现，出现说明整个网页都解析失败
            encrypted_password = encryptPassword(password);
            if (encrypted_password.empty()) {
                return LoginResult(ZfwErrorCode::LOGIC_PASSWORD_ENCRYPTION_FAILED,
                    "Password encryption failed.");
            }

            // --- 📌 核心步骤: 直接 POST 到根目录进行认证和会话初始化 ---
            session.SetUrl(cpr::Url{ "https://zfw.xidian.edu.cn/" });
            session.SetHeader(cpr::Header{
                {"Content-Type", "application/x-www-form-urlencoded"},
                {"Referer", "https://zfw.xidian.edu.cn/"},
                {"Origin", "https://zfw.xidian.edu.cn"}
                });
            session.SetPayload(cpr::Payload{
                {"_csrf-8800", initial_csrf_token},
                {"LoginForm[username]", username},
                {"LoginForm[password]", encrypted_password},
                {"LoginForm[verifyCode]", captcha_code}
                });
            cpr::Response login_response;
            try {
                login_response = session.Post();
            }
            catch (const cpr::Error& e) {
                return LoginResult(ZfwErrorCode::NETWORK_CPR_ERROR,
                    "CPR library error during login request: " + std::string(e.message));
            }

            if (login_response.status_code == 302 &&
                login_response.header["Location"].find("/home") != std::string::npos) {
                // 登录成功
                login_succeeded = true;
                break;
            }
            else if (login_response.status_code == 200) {
                if (login_response.text.find("验证码错误") != std::string::npos) {
                    // 验证码错误，重试
                    continue;
                }
                else if (login_response.text.find("用户名或密码错误") != std::string::npos) {
                    return LoginResult(ZfwErrorCode::LOGIC_USERNAME_PASSWORD_ERROR,
                        "用户名或密码错误。");
                }
                else if (login_response.text.find("登录超时，请重新登陆") != std::string::npos) {
                    return LoginResult(ZfwErrorCode::LOGIC_LOGIN_TIMEOUT,
                        "登录超时或csrf构造出错");
                }
                else {
                    return LoginResult(ZfwErrorCode::LOGIC_UNEXPECTED_RESPONSE,
                        "Unexpected login response content");
                }
            }
            else {
                return LoginResult(ZfwErrorCode::NETWORK_LOGIN_REQUEST_FAILED,
                    "Login request failed with status code: " + std::to_string(login_response.status_code));
            }
        }

        if (!login_succeeded) {
            return LoginResult(ZfwErrorCode::CAPTCHA_VALIDATION_FAILED,
                "Login failed after multiple attempts (likely captcha issues).");
        }

        // --- 📌 最后一步: 获取Dashboard页面 ---
        try {
            //std::wcout << "[Debug] Final Step: GETing dashboard from /home..." << std::endl;
            session.SetUrl(cpr::Url{ "https://zfw.xidian.edu.cn/home" });
            session.SetPayload({});
            session.SetHeader({});

            cpr::Response dashboard_r = session.Get();

            if (dashboard_r.status_code == 200 && dashboard_r.text.find("query-user") != std::string::npos) {
                LoginResult result(ZfwErrorCode::SUCCESS, "Login and data fetch successful.");
                parseDashboard(dashboard_r.text, result.user_info);
                return result;
            }
            else {
                return LoginResult(ZfwErrorCode::NETWORK_GET_DASHBOARD_FAILED,
                    "Could not fetch dashboard. Status: " + std::to_string(dashboard_r.status_code));
            }
        }
        catch (const cpr::Error& e) {
            return LoginResult(ZfwErrorCode::NETWORK_CPR_ERROR,
                "CPR library error during dashboard request: " + std::string(e.message));
        }
        catch (const std::exception& e) {
            return LoginResult(ZfwErrorCode::SYSTEM_UNKNOWN_ERROR,
                "Unknown exception during dashboard request: " + std::string(e.what()));
        }
    }
};

// --- ZfwManager 公开接口的实现 ---
ZfwManager::ZfwManager(const std::wstring& model_path) { impl = new ZfwManagerImpl(model_path); }
ZfwManager::~ZfwManager() { delete impl; }
LoginResult ZfwManager::login(const std::string& username, const std::string& password) { return impl->doLogin(username, password); }
std::string ZfwManager::getCsrfToken() const { return impl->csrf_token; }
std::string ZfwManager::getPublicKey() const { return impl->public_key; }