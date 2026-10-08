# dsh-qoder-connect

将 Qoder CN（国内版）桌面 App 的模型接入 DeepSeek Harness。复用桌面 App 的登录状态（解密本地 Chromium OSCrypt 加密凭据，全程零交互、无需 OAuth），在 DSH 模型选择器中出现「Qoder」分组。

仅供个人学习和研究使用；请遵守 Qoder 服务条款。签名方案（COSY）与上游协议参照 MIT 许可的 [qoder2api](https://github.com/) 项目的公开实现移植。

## 功能

- **零交互登录**：自动扫描 `%APPDATA%` 下所有 `com.qodercn.app.*` 数据目录（stable / beta / dev 等渠道变体），解密其中的 `auth.v1.dat`（Chromium OSCrypt：DPAPI 保护的 AES-256-GCM）。首次运行用 PowerShell 一次性导出各变体的密钥到 `<DSH_HOME>\.qoder-connect\oscrypt-<渠道>.key`（如 `oscrypt-stable.key`；旧版单文件缓存 `oscrypt.key` 会被自动复制为 stable 的缓存，原文件保留），之后纯 node 解密。多个候选都有凭据时优先 stable，其余按目录 mtime 新者优先；解密失败会自动作废缓存并重新导出一次。桌面 App 刷新令牌时按文件 mtime 自动跟随，签名会话在令牌轮换后自动重建。
- **显式路径优先**：设置卡 `dataDir` 字段（或环境变量 `QODER_DATA_DIR`）可直接指定数据目录、甚至直接指到 `auth.v1.dat` 文件，显式指定优先于自动扫描；显式路径解不开时自动回落到扫描。
- **动态模型目录**：完整列出上游模型目录（assistant 分组，不过滤），10 分钟自动刷新；模型名后照 WorkBuddy 的样式标注积分倍率（` · x0.5`，免费的标 ` · 免费`）。上游的 `enable` 标记与账号余额联动（点数耗尽即变 false），不代表模型本身不可用，因此不据此隐藏模型。
- **工具调用透传**：上游返回的 `tool_calls` 原样平接进 OpenAI 兼容响应（流式 delta 与非流式 message 双路）。
- **推理开关**：按模型的 `is_reasoning` 标记决定是否透传思考强度。

## 工作原理

1. **凭据**：扫描 `%APPDATA%\com.qodercn.app.*` 候选目录 → 每个候选用各自变体的密钥缓存（`oscrypt-<渠道>.key`，缺失时经 `Local State → os_crypt.encrypted_key`（DPAPI）现导）→ 解 `auth.v1.dat`（"v10" + nonce + cipher + tag）→ 谁先解出有效 dt- 令牌用谁（stable 优先，其次目录 mtime 新者优先）。一个凭据都解不出时，报错会提示：先确认 Qoder 桌面程序已启动并登录过（扫描模型列表与路径期间需保持程序处于启动状态）；首次使用请先在 Qoder 里完成一次登录。
2. **COSY 签名**：设备指纹派生（md5/sha512 截断）→ RSA(PKCS1) 加密 16 字符临时密钥 → AES-CBC 加密身份载荷 → 请求签名 = md5(payloadB64\n cosyKey\n date\n body\n pathSig)。请求体经自定义字母表 base64 变体编码（先三段重排再做字符映射，`=` → `$`）。
3. **翻译**：聊天走 `gateway.qoder.com.cn` 的 `agent_chat_generation` SSE，上游帧是 `{headers, body, statusCodeValue}` 信封——body 可能是字符串、对象或字面量 `"null"`，三种形态都兜住。消息结构按上游要求重建（user 用 contents 数组；`developer` 角色折叠为 `system`）。
4. **注册**：loopback OpenAI 兼容小门 + `ctx.llm.registerAdapter` 注册 `qoder` provider。

## 已知限制

- 仅支持国内版（CN）。
- 换电脑 / 换渠道后首次使用需该渠道的 Qoder 桌面程序在本机登录过一次，否则密钥导不出、凭据解不开。
- 请求体基于抓包得到的 baseprompt 模板（`baseprompt.json`），上游结构变化时需随之更新。
- 依赖 Qoder 客户端私有接口，Qoder 更新后可能需要调整。

## 免责声明

- 本项目仅供个人学习和研究使用，仅驱动使用者自己的 Qoder 账号在本机调用，请勿用于商业用途。
- 因使用本项目产生的任何后果（包括但不限于账号被限制、额度被清空、服务中断），由使用者自行承担。
- 本项目与 Qoder、阿里云、DeepSeek 均无关联，未获其授权或认可。

## 许可证

[MIT](./LICENSE)
