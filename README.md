# LuCI WebAuthn Passkey Authentication

[English](#english) | [中文](#中文)

---

## English

A LuCI application that adds WebAuthn/FIDO2 passkey authentication support to OpenWrt routers, enabling passwordless and secure login using hardware security keys, biometric sensors, or platform authenticators.

### Features

- 🔐 **Passwordless Login**: Login to your OpenWrt router using passkeys (security keys, fingerprint, Face ID, etc.)
- 🔑 **Multi-Device Support**: Register and manage multiple passkeys for different devices
- 🛡️ **Enhanced Security**: WebAuthn provides phishing-resistant authentication using public-key cryptography
- 📱 **Cross-Platform**: Works with any WebAuthn-compatible authenticator (YubiKey, Windows Hello, Touch ID, Android biometrics, etc.)
- 🎨 **Seamless Integration**: Integrates naturally into the LuCI login page and administration interface
- 🌐 **HTTPS Required**: Enforces secure context for WebAuthn operations

### Architecture

The application consists of three layers:

```
Browser (JavaScript)
    ↓ WebAuthn API (navigator.credentials)
    ↓ JSON-RPC over HTTP
LuCI (ucode middleware)
    ↓ CLI execution
webauthn-helper (Rust backend)
    ↓ File system (credential storage)
```

**Components:**

1. **Frontend (Browser JS)**:
   - `/www/luci-static/resources/view/system/webauthn.js` - Passkey management interface
   - `/www/luci-static/resources/view/plugins/25e715cf23e44e35bc6763e804d85b85.js` - Plugin configuration interface
   - `/www/luci-static/plugins/25e715cf23e44e35bc6763e804d85b85/challenge.js` - Login challenge script

2. **Middleware (ucode)**:
   - `/usr/share/rpcd/ucode/webauthn.uc` - RPC backend that bridges browser and CLI
   - `/usr/share/ucode/luci/plugins/auth/login/25e715cf23e44e35bc6763e804d85b85.uc` - Authentication plugin

3. **Backend (Rust CLI)**:
   - Uses [webauthn-helper](https://github.com/Tokisaki-Galaxy/webauthn-helper/) for WebAuthn protocol handling and credential management

### Backend Dependency

This application requires the **[webauthn-helper](https://github.com/Tokisaki-Galaxy/webauthn-helper/)** Rust CLI tool to function. The helper binary must be installed at `/usr/bin/webauthn-helper`.

The webauthn-helper handles:
- WebAuthn protocol operations (registration, authentication)
- Credential storage and management
- Challenge generation and validation
- Security policy enforcement

### Prerequisites

1. **LuCI plugin auth architecture**: Requires LuCI plugin UI + auth login plugin mechanism
2. **HTTPS Configuration**: WebAuthn requires a secure context (HTTPS or localhost)
3. **Modern Browser**: Browser with WebAuthn API support (Chrome 67+, Firefox 60+, Safari 13+, Edge 18+)
4. **webauthn-helper**: The backend CLI tool must be installed

### Installation

#### 1. Install webauthn-helper

Download and install the webauthn-helper binary for your architecture from the [releases page](https://github.com/Tokisaki-Galaxy/webauthn-helper/releases):

```bash
# Example for x86_64
wget https://github.com/Tokisaki-Galaxy/webauthn-helper/releases/latest/download/webauthn-helper-x86_64
chmod +x webauthn-helper-x86_64
mv webauthn-helper-x86_64 /usr/bin/webauthn-helper
```

#### 2. Install luci-app-webauthn

**Option A: From IPK Package (Recommended)**

Download the IPK package for your architecture and install:

```bash
# Example for x86_64
wget https://github.com/Tokisaki-Galaxy/luci-app-webauthn/releases/latest/download/luci-app-webauthn_all.ipk
opkg install luci-app-webauthn_all.ipk
```

**Option B: Manual Installation**

Copy the files from the `luci-app-webauthn` directory to your OpenWrt system:

```bash
# Copy all files from luci-app-webauthn/root/ to system root
cp -r luci-app-webauthn/root/* /

# Copy web resources from luci-app-webauthn/htdocs/ to web root
cp -r luci-app-webauthn/htdocs/* /www/

# Clear LuCI cache and restart services
rm -f /tmp/luci-indexcache*
/etc/init.d/rpcd restart
```

#### 3. Configure HTTPS (if not already configured)

WebAuthn requires HTTPS. If accessing your router via HTTP:

1. Generate an SSL certificate (or use Let's Encrypt)
2. Configure uhttpd to use HTTPS
3. Access your router via `https://your-router-ip/`

For testing purposes, you can also access via `http://localhost/` if you have SSH port forwarding set up.

### Usage

#### Registering a Passkey

1. Log in to your OpenWrt router's LuCI interface
2. Navigate to **System** → **Administration** → **Passkeys**
3. Click **Register New Passkey**
4. Follow your browser's prompts to create a passkey using:
   - A USB security key (e.g., YubiKey)
   - Biometric sensor (fingerprint, Face ID, Windows Hello)
   - Device PIN or password
5. Give your passkey a memorable name
6. The new passkey will appear in the management table

In **System → Plugins**, you can set `priority` for WebAuthn auth plugin. Lower values run earlier.

#### Logging in with a Passkey

1. Go to the LuCI login page
2. Look for the **🔑 Passkey** button below the password form
3. Click the button
4. Follow your browser's prompts to authenticate with your passkey
5. You'll be logged in automatically upon successful authentication

#### Managing Passkeys

In the Passkeys management page (**System** → **Administration** → **Passkeys**), you can:

- **View all registered passkeys** with details:
  - Device name
  - Registration date
  - Last used date
  - User verification status
- **Rename passkeys**: Click on the device name to edit
- **Delete passkeys**: Click the delete button to remove a passkey

### File Structure

```
luci-app-webauthn/
├── Makefile
├── htdocs/
│   └── luci-static/resources/view/system/
│       └── webauthn.js
└── root/
    ├── etc/uci-defaults/luci-app-webauthn
    ├── usr/share/rpcd/...
    ├── usr/share/ucode/luci/plugins/auth/login/25e715cf23e44e35bc6763e804d85b85.uc
    └── www/luci-static/
        ├── resources/view/plugins/25e715cf23e44e35bc6763e804d85b85.js
        └── plugins/25e715cf23e44e35bc6763e804d85b85/challenge.js
```

### Security Considerations

1. **HTTPS is Mandatory**: WebAuthn will not work over plain HTTP (except localhost). Always use HTTPS in production.

2. **Origin Validation**: The middleware automatically passes the correct origin to webauthn-helper. Do not bypass this.

3. **Credential Storage**: Credentials are stored by webauthn-helper in a secure format. Ensure proper file permissions.

4. **Clone Detection**: The backend includes clone detection. If a warning appears, investigate immediately.

5. **Backup**: Passkeys cannot be recovered if lost. Always register multiple passkeys or maintain password access.

### Development

#### Testing

The project includes test mocks in `src/mocks/` for development without a full OpenWrt environment.

#### Building

To build the OpenWrt package:

```bash
# From OpenWrt buildroot with this feed added
make package/luci-app-webauthn/compile
```

#### Code Quality

Run the following checks before submitting changes:

```bash
# TypeScript type checking
npx tsc -b

# ESLint
npm run lint

# Prettier formatting
npx prettier --write .

# Check for unused code
npx knip
```

### Troubleshooting

**Passkey button is disabled on login page**
- Ensure webauthn-helper is installed at `/usr/bin/webauthn-helper`
- Check that you're accessing via HTTPS or localhost
- Open browser console for JavaScript errors

**"Security Check Failed: Domain mismatch" error**
- Ensure you're accessing the router using the same domain/IP that was used during passkey registration
- Check that HTTPS certificates match the domain

**Passkey not found**
- Ensure the passkey is registered on the current device/browser
- Try a different passkey if you have multiple registered

**General WebAuthn errors**
- Check browser console for detailed error messages
- Verify that your browser supports WebAuthn
- Ensure cookies and JavaScript are enabled

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Run code quality checks
5. Submit a pull request

### License

This project is licensed under the Apache License 2.0. See the Makefile for details.

### Related Projects

- **Backend**: [webauthn-helper](https://github.com/Tokisaki-Galaxy/webauthn-helper/) - Rust CLI for WebAuthn operations
- **OpenWrt**: [openwrt/openwrt](https://github.com/openwrt/openwrt) - The OpenWrt Project
- **LuCI**: [openwrt/luci](https://github.com/openwrt/luci) - OpenWrt Configuration Interface

---

## 中文

为 OpenWrt 路由器添加 WebAuthn/FIDO2 通行密钥认证支持的 LuCI 应用，使用硬件安全密钥、生物识别传感器或平台身份验证器实现无密码安全登录。

### 功能特性

- 🔐 **无密码登录**：使用通行密钥（安全密钥、指纹、Face ID 等）登录 OpenWrt 路由器
- 🔑 **多设备支持**：为不同设备注册和管理多个通行密钥
- 🛡️ **增强安全性**：WebAuthn 使用公钥加密技术提供抗钓鱼认证
- 📱 **跨平台兼容**：适用于任何兼容 WebAuthn 的身份验证器（YubiKey、Windows Hello、Touch ID、Android 生物识别等）
- 🎨 **无缝集成**：自然集成到 LuCI 登录页面和管理界面
- 🌐 **需要 HTTPS**：为 WebAuthn 操作强制使用安全上下文

### 架构

应用程序由三层组成：

```
浏览器 (JavaScript)
    ↓ WebAuthn API (navigator.credentials)
    ↓ JSON-RPC over HTTP
LuCI (ucode 中间件)
    ↓ CLI 执行
webauthn-helper (Rust 后端)
    ↓ 文件系统（凭据存储）
```

**组件说明：**

1. **前端（浏览器 JS）**：
   - `/www/luci-static/resources/view/system/webauthn.js` - 通行密钥管理界面
   - `/www/luci-static/resources/view/plugins/25e715cf23e44e35bc6763e804d85b85.js` - 插件配置界面
   - `/www/luci-static/plugins/25e715cf23e44e35bc6763e804d85b85/challenge.js` - 登录挑战脚本

2. **中间件（ucode）**：
   - `/usr/share/rpcd/ucode/webauthn.uc` - 连接浏览器和 CLI 的 RPC 后端
   - `/usr/share/ucode/luci/plugins/auth/login/25e715cf23e44e35bc6763e804d85b85.uc` - 认证插件

3. **后端（Rust CLI）**：
   - 使用 [webauthn-helper](https://github.com/Tokisaki-Galaxy/webauthn-helper/) 处理 WebAuthn 协议和凭据管理

### 后端依赖

此应用需要 **[webauthn-helper](https://github.com/Tokisaki-Galaxy/webauthn-helper/)** Rust CLI 工具才能运行。该辅助程序二进制文件必须安装在 `/usr/bin/webauthn-helper`。

webauthn-helper 负责处理：
- WebAuthn 协议操作（注册、认证）
- 凭据存储和管理
- 挑战生成和验证
- 安全策略执行

### 前置要求

1. **LuCI 插件认证架构**：需要支持 `luci_plugins` 与 auth login 插件机制
2. **HTTPS 配置**：WebAuthn 需要安全上下文（HTTPS 或 localhost）
3. **现代浏览器**：支持 WebAuthn API 的浏览器（Chrome 67+、Firefox 60+、Safari 13+、Edge 18+）
4. **webauthn-helper**：必须安装后端 CLI 工具

### 安装

#### 1. 安装 webauthn-helper

从[发布页面](https://github.com/Tokisaki-Galaxy/webauthn-helper/releases)下载并安装适合您架构的 webauthn-helper 二进制文件：

```bash
# x86_64 架构示例
wget https://github.com/Tokisaki-Galaxy/webauthn-helper/releases/latest/download/webauthn-helper-x86_64
chmod +x webauthn-helper-x86_64
mv webauthn-helper-x86_64 /usr/bin/webauthn-helper
```

#### 2. 安装 luci-app-webauthn

**方式 A：从 IPK 包安装（推荐）**

下载适合您架构的 IPK 包并安装：

```bash
# x86_64 架构示例
wget https://github.com/Tokisaki-Galaxy/luci-app-webauthn/releases/latest/download/luci-app-webauthn_all.ipk
opkg install luci-app-webauthn_all.ipk
```

**方式 B：手动安装**

将 `luci-app-webauthn` 目录中的文件复制到 OpenWrt 系统：

```bash
# 从 luci-app-webauthn/root/ 复制所有文件到系统根目录
cp -r luci-app-webauthn/root/* /

# 从 luci-app-webauthn/htdocs/ 复制 Web 资源到 Web 根目录
cp -r luci-app-webauthn/htdocs/* /www/

# 清除 LuCI 缓存并重启服务
rm -f /tmp/luci-indexcache*
/etc/init.d/rpcd restart
```

#### 3. 配置 HTTPS（如果尚未配置）

WebAuthn 需要 HTTPS。如果通过 HTTP 访问路由器：

1. 生成 SSL 证书（或使用 Let's Encrypt）
2. 配置 uhttpd 使用 HTTPS
3. 通过 `https://your-router-ip/` 访问路由器

用于测试目的时，如果设置了 SSH 端口转发，也可以通过 `http://localhost/` 访问。

### 使用方法

#### 注册通行密钥

1. 登录到 OpenWrt 路由器的 LuCI 界面
2. 导航至 **系统** → **管理权** → **通行密钥**
3. 点击 **注册新通行密钥**
4. 按照浏览器提示使用以下方式创建通行密钥：
   - USB 安全密钥（例如 YubiKey）
   - 生物识别传感器（指纹、Face ID、Windows Hello）
   - 设备 PIN 或密码
5. 为您的通行密钥指定一个便于记忆的名称
6. 新通行密钥将出现在管理表格中

在 **系统 → 插件** 中可设置 WebAuthn 认证插件 `priority`，数值越小越先执行。

#### 使用通行密钥登录

1. 访问 LuCI 登录页面
2. 在密码表单下方寻找 **🔑 通行密钥** 按钮
3. 点击该按钮
4. 按照浏览器提示使用您的通行密钥进行身份验证
5. 成功验证后，您将自动登录

#### 管理通行密钥

在通行密钥管理页面（**系统** → **管理权** → **通行密钥**）中，您可以：

- **查看所有已注册的通行密钥**，包括详细信息：
  - 设备名称
  - 注册日期
  - 最后使用日期
  - 用户验证状态
- **重命名通行密钥**：点击设备名称进行编辑
- **删除通行密钥**：点击删除按钮移除通行密钥

### 文件结构

```
luci-app-webauthn/
├── Makefile
├── htdocs/
│   └── luci-static/resources/view/system/
│       └── webauthn.js
└── root/
    ├── etc/uci-defaults/luci-app-webauthn
    ├── usr/share/rpcd/...
    ├── usr/share/ucode/luci/plugins/auth/login/25e715cf23e44e35bc6763e804d85b85.uc
    └── www/luci-static/
        ├── resources/view/plugins/25e715cf23e44e35bc6763e804d85b85.js
        └── plugins/25e715cf23e44e35bc6763e804d85b85/challenge.js
```

### 安全注意事项

1. **强制使用 HTTPS**：WebAuthn 在普通 HTTP 上不工作（localhost 除外）。生产环境中请始终使用 HTTPS。

2. **来源验证**：中间件会自动将正确的来源传递给 webauthn-helper。请勿绕过此机制。

3. **凭据存储**：凭据由 webauthn-helper 以安全格式存储。确保设置正确的文件权限。

4. **克隆检测**：后端包含克隆检测功能。如果出现警告，请立即调查。

5. **备份**：通行密钥丢失后无法恢复。请始终注册多个通行密钥或保留密码访问方式。

### 开发

#### 测试

项目在 `src/mocks/` 中包含测试模拟数据，用于在没有完整 OpenWrt 环境的情况下进行开发。

#### 构建

构建 OpenWrt 包：

```bash
# 从添加了此 feed 的 OpenWrt buildroot 中执行
make package/luci-app-webauthn/compile
```

#### 代码质量

提交更改前运行以下检查：

```bash
# TypeScript 类型检查
npx tsc -b

# ESLint 检查
npm run lint

# Prettier 格式化
npx prettier --write .

# 检查未使用的代码
npx knip
```

### 故障排除

**登录页面上的通行密钥按钮被禁用**
- 确保 webauthn-helper 已安装在 `/usr/bin/webauthn-helper`
- 检查是否通过 HTTPS 或 localhost 访问
- 打开浏览器控制台查看 JavaScript 错误

**"安全检查失败：域名不匹配"错误**
- 确保使用与注册通行密钥时相同的域名/IP 访问路由器
- 检查 HTTPS 证书是否与域名匹配

**找不到通行密钥**
- 确保通行密钥已在当前设备/浏览器上注册
- 如果有多个已注册的通行密钥，尝试使用其他通行密钥

**一般 WebAuthn 错误**
- 检查浏览器控制台以获取详细错误消息
- 验证您的浏览器是否支持 WebAuthn
- 确保启用了 Cookie 和 JavaScript

### 贡献

欢迎贡献！请：

1. Fork 此仓库
2. 创建功能分支
3. 使用清晰的提交消息进行更改
4. 运行代码质量检查
5. 提交 Pull Request

### 许可证

本项目采用 Apache License 2.0 许可。详见 Makefile。

### 相关项目

- **后端**：[webauthn-helper](https://github.com/Tokisaki-Galaxy/webauthn-helper/) - 用于 WebAuthn 操作的 Rust CLI
- **OpenWrt**：[openwrt/openwrt](https://github.com/openwrt/openwrt) - OpenWrt 项目
- **LuCI**：[openwrt/luci](https://github.com/openwrt/luci) - OpenWrt 配置界面
