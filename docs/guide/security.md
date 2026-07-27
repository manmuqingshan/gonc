# 安全与加密

网络安全是 `gonc` 设计的首要原则。不同于传统 `netcat` 默认明文传输，`gonc` 内置了企业级的加密和认证机制，确保你的数据在公共网络（如互联网、公共 WiFi）中传输时的机密性与完整性。

---

## 🔐 TLS 加密传输

`gonc` 支持基于 TLS 1.3 的标准化加密传输，这与 HTTPS 网站使用的安全技术相同。

### 启用 TLS

只需添加 **`-tls`** 参数，即可将普通的 TCP 连接升级为加密连接。

=== "服务端"
    ```bash
    # 自动生成临时证书并监听加密端口
    gonc -tls -l 8443
    ```

=== "客户端"
    ```bash
    # 连接加密端口
    gonc -tls <target_ip> 8443
    ```

### 版本控制
默认情况下，`gonc` 会自动协商最高的 TLS 版本。你也可以强制指定版本以兼容旧系统或满足合规要求：

* `-tls13`: 强制 TLS 1.3 (推荐，最快且最安全)
* `-tls12`: 强制 TLS 1.2
* `-tls10` / `-tls11`: 旧版本 (仅用于调试，不推荐)

---

## 🔑 PSK 身份认证 (双向认证)

在开放网络中，仅有 TLS 加密是不够的，你还需要确认连接对方的身份（防止端口扫描或中间人攻击）。

`gonc` 使用 **PSK (Pre-Shared Key)** 机制来实现轻量级的**双向认证**。

**原理**：
`-psk` 指定的字符串不仅作为密码，还会参与 TLS 密钥派生。只有持有相同 PSK 的双方才能完成 TLS 握手。如果 PSK 不匹配，连接会在握手阶段直接断开，数据流甚至不会进入应用层。

**用法**：

=== "服务端"
```bash
gonc -tls -psk mysecret123 -l 8443
```

=== "客户端"
```bash
gonc -tls -psk mysecret123 <target_ip> 8443
```

!!! success "安全性优势"
使用 `-psk` 后，`gonc` 实际上实现了 **mTLS (双向 TLS)** 的安全级别，但无需搭建复杂的 CA (证书授权中心) 来分发客户端证书。

---

## 📜 证书管理

默认情况下，`gonc` 会在启动时自动生成临时的自签名 ECDSA 证书。这对于临时任务非常方便，但在生产环境中，你可能需要加载自己的证书。

### 加载自定义证书

如果你拥有有效的域名证书（例如由 Let's Encrypt 签发），可以加载它以消除浏览器的警告。

```bash
gonc -l -local :443 -tls \
     -ssl-cert /path/to/fullchain.pem \
     -ssl-key /path/to/privkey.pem

```

### 客户端证书验证

在客户端模式下，使用 **`-verify`** 参数强制验证服务端证书的有效性。这通常配合自定义证书使用，以防止伪造的服务端。

```bash
# 如果服务端证书无效或主机名不匹配，连接将被拒绝
gonc -tls -verify example.com 443

```

### SNI 伪装

在受限网络环境中，你可能需要伪装 TLS 握手时的 Server Name Indication (SNI)。

```bash
# 伪装成访问 www.google.com
gonc -tls -sni www.google.com <target_ip> 443

```

---

## 🛡️ P2P 安全通讯

在 `-p2p` 模式下，安全机制是自动且强制的。双方约定的口令作为 PSK（Pre-Shared Key），默认启用TLS + PSK模式。

---

## 🚫 ACL 访问控制

除了加密，`gonc` 还支持应用层的访问控制列表 (ACL)，用于精细控制谁可以连接，或谁可以被访问。

**参数**：
`-acl <file>`

**ACL 文件格式**：
ACL 文件是一个简单的文本文件，支持入站和出站的允许、拒绝规则。`allow_inbound` 或
`allow_outbound` 配置段一旦出现，就会为对应方向启用默认拒绝模式；显式 `deny` 规则优先。

- `allow_inbound`：按来源 IPv4、IPv6 或 CIDR 放行。
- `allow_outbound`：按精确目标 host 和端口放行，支持 `host:port` 和 `host:start-end`。
- `deny_inbound`：按来源 IP/CIDR 拒绝，可用 `!` 添加更具体的例外。
- `deny_outbound`：按目标 IP/CIDR/域名拒绝，可用 `!` 添加例外。
- IPv6 出站允许规则必须写成 `[IPv6]:port`。
- 允许配置段为空时，表示拒绝该方向的全部连接。

**`acl.txt` 示例**：

```text
# 只允许这些来源 IP
[allow_inbound]
203.0.113.0/24
2001:db8:100::/48

# 即使位于允许网段内，也拒绝这个来源
[deny_inbound]
203.0.113.66

# 只允许这些目标 host+port
[allow_outbound]
api.example.com:443
192.168.1.30:8000-8999
[2001:db8::20]:10000-10100

# 额外禁止访问回环和内网地址；域名解析出的 IP 也会检查
[deny_outbound]
127.0.0.0/8
10.0.0.0/8
192.168.0.0/16
172.16.0.0/12
::1
::/0
deny-example.com
*.deny-example.com

```

**应用示例**：

```bash
# 启动 SOCKS5 代理，并加载访问控制规则
gonc -e ":s5s" -acl acl.txt -k -l 1080

```

---

## ⚠️ 安全最佳实践总结

1. **永远不要在公网上裸奔**：只要通过公网连接，**务必**加上 `-tls`。
2. **总是使用 PSK**：`-psk` 是最简单有效的防扫描、防未授权访问手段。
3. **P2P 口令要复杂**：P2P Session Key 充当了发现密钥，如果过于简单（如 `123`），可能会被其他人误撞上。
4. **敏感服务限制 IP**：使用 `-local 127.0.0.1:port` 确保敏感服务（如未加密的 HTTP）只监听在本地，不暴露给局域网。

