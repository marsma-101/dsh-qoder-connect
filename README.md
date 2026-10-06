# dsh-qoder-connect

将 Qoder CN（国内版）桌面 App 的模型接入 DeepSeek Harness。复用桌面 App 的登录状态（解密本地 Chromium OSCrypt 加密凭据，全程零交互、无需 OAuth），在 DSH 模型选择器中出现「Qoder」分组。

仅供个人学习和研究使用；请遵守 Qoder 服务条款。签名方案（COSY）与上游协议参照 MIT 许可的 [qoder2api](https://github.com/) 项目的公开实现移植。

## 功能

- **零交互登录**：解密 `%APPDATA%\com.qodercn.app.stable\auth.v1.dat`（Chromium OSCrypt：DPAPI 保护的 AES-256-GCM）。首次运行用 PowerShell 一次性导出密钥到 `<DSH_HOME>\.qoder-connect\oscrypt.key`，之后纯 node 解密。桌面 App 刷新令牌时按文件 mtime 自动跟随，签名会话在令牌轮换后自动重建。
- **动态模型目录**：按 `enable` 过滤拉取可用模型（assistant 分组），10 分钟自动刷新；模型名后标注倍率与推理能力。
- **工具调用透传**：上游返回的 `tool_calls` 原样平接进 OpenAI 兼容响应（流式 delta 与非流式 message 双路）。
- **推理开关**：按模型的 `is_reasoning` 标记决定是否透传思考强度。

## 工作原理

1. **凭据**：`Local State → os_crypt.encrypted_key`（DPAPI）解出 AES 密钥 → 解 `auth.v1.dat`（"v10" + nonce + cipher + tag）→ 得到 dt- 令牌与用户信息。
2. **COSY 签名**：设备指纹派生（md5/sha512 截断）→ RSA(PKCS1) 加密 16 字符临时密钥 → AES-CBC 加密身份载荷 → 请求签名 = md5(payloadB64\n cosyKey\n date\n body\n pathSig)。请求体经自定义字母表 base64 变体编码（先三段重排再做字符映射，`=` → `$`）。
3. **翻译**：聊天走 `gateway.qoder.com.cn` 的 `agent_chat_generation` SSE，上游帧是 `{headers, body, statusCodeValue}` 信封——body 可能是字符串、对象或字面量 `"null"`，三种形态都兜住。消息结构按上游要求重建（user 用 contents 数组；`developer` 角色折叠为 `system`）。
4. **注册**：loopback OpenAI 兼容小门 + `ctx.llm.registerAdapter` 注册 `qoder` provider。

## 已知限制

- 仅支持国内版（CN）。
- 请求体基于抓包得到的 baseprompt 模板（`baseprompt.json`），上游结构变化时需随之更新。
- 依赖 Qoder 客户端私有接口，Qoder 更新后可能需要调整。

## 免责声明

- 本项目仅供个人学习和研究使用，仅驱动使用者自己的 Qoder 账号在本机调用，请勿用于商业用途。
- 因使用本项目产生的任何后果（包括但不限于账号被限制、额度被清空、服务中断），由使用者自行承担。
- 本项目与 Qoder、阿里云、DeepSeek 均无关联，未获其授权或认可。

## 许可证

[MIT](./LICENSE)
