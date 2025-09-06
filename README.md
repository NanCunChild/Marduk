# 西电校园网络诊断工具 (Marduk)

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Language](https://img.shields.io/badge/language-C%2B%2B17-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

*一个专为西电校园网环境定制的轻量级网络诊断工具*

**由 NanCunChild 倾力打造**

</div>

---

## 📋 项目概述

Marduk 是一个专门为西安电子科技大学校园网环境设计的**多功能网络诊断与优化工具**。该工具采用现代 C++ 开发，通过高度解耦的 DLL 架构设计，为普通用户提供简单易用的网络问题解决方案。

### 🎯 设计目标

- **零门槛使用**：普通用户无需具备网络技术背景即可使用
- **问题快速定位**：自动化诊断常见校园网问题
- **专业报告生成**：为疑难杂症提供详细的诊断报告
- **轻量化设计**：最少外部依赖，快速部署
- **模块化架构**：高度解耦，便于维护和扩展

---

## 🌟 核心功能

### 🔐 统一认证登录
- **智能验证码识别**：基于 ONNX 深度学习模型，自动识别校园网登录验证码
- **安全凭据管理**：支持 RSA 加密的密码安全传输
- **会话状态跟踪**：自动维护登录状态，获取用户详细信息

### 🛠️ DNS 代理服务
- **一键部署**：自动安装和配置 Acrylic DNS Proxy 服务
- **智能规则管理**：
  - 添加自定义 DNS 解析规则
  - 删除指定域名的解析记录
  - 批量清理所有自定义规则
- **服务状态监控**：实时查看 DNS 服务运行状态

### 🔍 全方位网络诊断
- **连通性测试**：多目标 Ping 测试，支持 ICMP 和 TCP 两种模式
- **DNS 解析测试**：验证域名解析服务的可用性和响应时间
- **TCP 连接测试**：检测特定端口的连接状态
- **系统信息收集**：
  - 网络接口配置信息
  - 代理服务器设置
  - 路由表详细信息
  - 系统环境参数

### 📊 智能报告生成
- **双格式输出**：
  - 📄 **文本报告**：简洁的纯文本格式，易于分享
  - 🌐 **HTML 报告**：美观的可视化报告，支持交互功能
- **UTF-8 无 BOM 编码**：确保跨平台兼容性
- **诊断建议**：基于测试结果提供智能化的问题解决建议

### ⚡ 一键优化
- **网络环境优化**：自动部署 DNS 代理服务
- **IPv6 问题修复**：针对校园网 IPv6 连接问题进行优化
- **批量配置应用**：一键应用最佳网络配置

---

## 🏗️ 架构设计

### 模块化 DLL 架构

```
Marduk (主程序)
├── ZfwInteractionDll     # 统一认证交互模块
│   ├── 登录验证码识别
│   ├── RSA 密码加密
│   └── 用户信息解析
├── DNSManagerDll         # DNS 服务管理模块
│   ├── Acrylic DNS 代理部署
│   ├── DNS 规则管理
│   └── 服务状态监控
└── NetworkDiagnosticDll  # 网络诊断模块
    ├── 多协议连通性测试
    ├── 系统信息收集
    └── 智能报告生成
```

### 🔧 技术栈

| 组件 | 技术选择 | 用途 |
|------|---------|------|
| **语言标准** | C++17/20 | 现代 C++ 特性支持 |
| **HTTP 请求** | CPR Library | 网络请求处理 |
| **HTML 解析** | Gumbo Parser | 网页内容解析 |
| **机器学习** | ONNX Runtime | 验证码识别模型 |
| **图像处理** | OpenCV | 验证码预处理 |
| **加密算法** | Crypto++ | RSA 加密支持 |
| **JSON 处理** | nlohmann::json | 数据序列化 |

---

## 💻 用户界面

### 命令行界面 (CLI)

```
--- 西电校园网辅助工具 (CLI v1.0) ---
欢迎使用！输入 'help' 查看所有可用命令。
🔑 当前运行模式: 管理员权限

> help

=== 无需权限的命令 ===
  login       - 登录 zfw.xidian.edu.cn 平台
  zfwinfo     - (需先登录) 显示当前登录用户的详细信息
  diagno      - 🔍 生成详细的网络诊断报告
  dnslist     - 列出所有当前DNS规则
  help        - 显示此帮助信息
  exit        - 退出程序

=== 需要管理员权限的命令 ===
  dnsdep      - 🔧 部署本地DNS代理服务
  dnsadd      - ➕ 添加一条自定义DNS规则
  dnsrm       - ➖ 删除一条DNS规则
  dnsclear    - 🗑️ 清空所有DNS规则
  pasopt      - ⚡ 一键优化网络设置

>
```

### 智能权限管理

- **动态权限检测**：普通用户启动时不强制要求管理员权限
- **按需提权**：仅在需要管理员权限的操作时提示用户授权
- **权限状态显示**：实时显示当前运行权限状态

---

## 📈 功能亮点

### 🤖 智能验证码识别
- **深度学习模型**：基于 CRNN (卷积递归神经网络) 的验证码识别
- **高识别准确率**：针对校园网验证码特点训练优化
- **自动重试机制**：识别失败时自动重新获取验证码

### 🌐 现代化报告界面
- **响应式设计**：支持桌面、平板、手机多端查看
- **交互功能丰富**：
  - 表格数据一键复制
  - 返回顶部快捷按钮
  - 键盘快捷键支持 (Ctrl+P 打印、F5 刷新确认)
- **视觉效果优秀**：渐变背景、阴影效果、动画过渡

---

## 🚀 快速开始

### 系统要求

- **操作系统**：Windows 10/11 (x64)
- **运行时库**：Microsoft Visual C++ 2019/2022 Redistributable
- **网络环境**：西安电子科技大学校园网

### 安装步骤

1. **下载程序包**
   ```
   下载 Marduk-v1.0-Release.zip
   解压到任意目录
   ```

2. **运行程序**
   ```
   双击 Marduk.exe 启动
   或在 PowerShell/CMD 中运行
   ```

3. **首次使用建议**
   ```
   > login          # 先登录校园网平台
   > diagno         # 生成诊断报告
   > pasopt         # 一键优化网络设置
   ```

---

## 📋 使用场景

### 🎓 普通用户场景

**场景 1：网络访问异常**
```bash
# 快速诊断网络问题
> diagno
> # 选择生成 HTML 报告，自动打开查看结果
```

**场景 2：DNS 解析缓慢**
```bash
# 一键部署 DNS 优化
> pasopt
> # 系统会自动部署本地 DNS 代理，优化解析速度
```

**场景 3：特定网站无法访问**
```bash
# 添加自定义 DNS 规则
> dnsadd
> # 输入 IP 和域名，绕过 DNS 污染
```

### 🔧 技术支持场景

**场景 1：用户反馈网络问题**
```bash
# 生成详细诊断报告
> diagno
> # 选择生成双格式报告，发送给技术支持分析
```

**场景 2：批量网络优化**
```bash
# 获取用户网络信息
> login
> zfwinfo
> pasopt
> # 完整的网络优化流程
```

---

## 🛡️ 安全与隐私

### 数据安全
- **本地处理**：所有敏感数据仅在本地处理，不上传到第三方服务器
- **RSA 加密**：登录密码采用 RSA 公钥加密传输
- **内存安全**：敏感信息使用后立即清零，防止内存泄露

### 隐私保护
- **最小权限原则**：仅在必要时请求管理员权限
- **透明操作**：所有网络操作均有详细日志记录
- **用户可控**：用户完全掌控个人信息的使用范围

---

## 🔧 开发指南

### 编译环境

```bash
# 系统要求
Windows 10/11 + Visual Studio 2019/2022
C++17/20 标准支持

# 依赖管理
vcpkg 包管理器
所需第三方库通过 vcpkg 自动安装

# 编译步骤
1. 克隆项目代码
2. 运行 vcpkg install
3. 在 Visual Studio 中打开解决方案
4. 选择 Release x64 配置编译
```

### 项目结构

```
Marduk/
├── Marduk/                    # 主程序
├── ZfwInteractionDll/         # 统一认证模块
├── DNSManagerDll/             # DNS管理模块  
├── NetworkDiagnosticDll/      # 网络诊断模块
├── TestApp/                   # 测试程序
├── vcpkg/                     # 包管理器
└── bin/                       # 编译输出目录
    └── x64/
        └── Release/
            ├── Marduk.exe
            ├── *.dll
            └── crnn_model.onnx
```

### 扩展开发

**添加新的诊断功能：**

```cpp
// 在 NetworkDiagnosticDll 中添加新测试
DiagnosticResult customTest(const std::vector<std::string>& targets, 
                           std::vector<CustomResult>& results);

// 在主程序中添加新命令
else if (command == L"custom") handleCustomTest();
```

**添加新的网络服务管理：**

```cpp
// 创建新的管理DLL
class NewServiceManager {
public:
    ServiceResult deployService();
    ServiceResult configureService(const ServiceConfig& config);
    ServiceResult monitorService();
};
```

---

## 🤝 贡献指南

### 贡献方式

1. **问题反馈**：通过 GitHub Issues 报告 Bug 或建议功能
2. **代码贡献**：提交 Pull Request 改进代码
3. **文档完善**：协助完善用户文档和开发文档
4. **测试验证**：在不同环境下测试程序稳定性

### 开发规范

- **代码风格**：遵循现代 C++ 最佳实践
- **注释要求**：关键函数必须包含详细的中文注释
- **错误处理**：统一使用错误码返回机制，避免异常跨DLL传递
- **内存管理**：优先使用智能指针，避免手动内存管理

---

## 📞 支持与反馈

### 获取帮助

- **学校网络答疑群**：遇到疑难问题可在群内咨询技术支持，2025级答疑群：1054961683
- **GitHub Issues**：[提交问题报告](https://github.com/NanCunChild/Marduk/issues)
- **邮件联系**：nancunchild@gmail.com

### 常见问题

**Q: 程序需要管理员权限吗？**
A: 普通诊断功能无需管理员权限。DNS 服务管理和系统网络配置修改需要管理员权限，程序会在需要时自动提示。

**Q: 支持其他学校的网络环境吗？**
A: 目前专门针对西电校园网优化，其他环境可能需要适配。

**Q: 诊断报告可以分享吗？**
A: 可以。诊断报告不包含个人敏感信息，可以安全地分享给技术支持人员。

---

## 📄 更新日志

### v1.0.0 (2025-09-06)

**🎉 首次发布**

**新增功能：**
- ✅ 统一认证平台自动登录
- ✅ 智能验证码识别系统
- ✅ DNS 代理服务一键部署
- ✅ 全方位网络诊断功能
- ✅ 双格式诊断报告生成
- ✅ 动态权限管理系统
- ✅ 现代化 CLI 用户界面

**技术特性：**
- ✅ 高度解耦的 DLL 模块架构
- ✅ C++17 标准兼容
- ✅ 零外部依赖的独立部署
- ✅ UTF-8/UTF-16 编码完美支持

---

## 📜 许可证

```
MIT License

Copyright (c) 2025 NCC (NanCunChild)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

---

<div align="center">

**让校园网络问题不再成为学习的障碍** 🌟

*Made with ❤️ by NCC Lab*

</div>

喵🐱~ NCC使用了Claude4完成这个README，真浪费真好看喵