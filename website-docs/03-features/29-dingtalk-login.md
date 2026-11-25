# 钉钉扫码登录

WeKnora 支持用钉钉扫码登录，把外部钉钉身份映射到本地账号，登录成功后再走既有的租户 RBAC。它与密码登录、OIDC 单点登录可以同时开启，互不影响。

## 与 OIDC 的区别

钉钉**不是**标准 OIDC 提供方：它没有 discovery 文档，也不签发可用 JWKS 验签的 `id_token`，而是提供一套私有 OAuth2 授权端点加 REST 通讯录接口。因此钉钉使用独立的 `dingtalk_auth` 配置段，而不是复用 `oidc_auth`。

| 能力 | OIDC | 钉钉 |
| --- | --- | --- |
| 授权端点 | discovery / 手工配置 | `login.dingtalk.com/oauth2/auth` |
| 换取令牌 | `POST` 表单 | `POST` JSON（`userAccessToken`） |
| 用户信息 | UserInfo / 验签 id_token | `GET /v1.0/contact/users/me` |
| 稳定用户标识 | `sub` | `unionId` |
| 首次登录后 | 签发本地 JWT | 签发本地 JWT（完全相同） |

## 配置

在 `.env` 中设置（完整注释见 `.env.example` 的 F4 段）：

```bash
DINGTALK_AUTH_ENABLE=true
DINGTALK_APP_KEY=dingxxxxxxxxxxxxxxxx
DINGTALK_APP_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# 可选：限定企业
DINGTALK_CORP_ID=dingxxxxxxxxxxxxxxxx
# 登录按钮展示名，默认「钉钉」
DINGTALK_PROVIDER_DISPLAY_NAME=钉钉
# 首次登录策略：create_personal / tenantless / deny
DINGTALK_PROVISIONING_MODE=tenantless
# 是否允许按邮箱匹配已有本地账号（默认关闭）
DINGTALK_BIND_BY_EMAIL=false
```

`dingtalk_auth.enable=true` 但缺少 `app_key` / `app_secret` 时，服务**启动即报错**，不会等到第一次登录才暴露问题。

### 钉钉开放平台侧

1. 在[钉钉开放平台](https://open.dingtalk.com/)创建「企业内部应用（H5 微应用）」。
2. 记录 **AppKey** / **AppSecret**。
3. 在应用的登录回调白名单中登记：
   ```text
   https://<你的域名>/api/v1/auth/dingtalk/callback
   ```
4. 如需按企业隔离，记录 CorpId 并配置 `DINGTALK_CORP_ID`。

## 登录流程

```text
浏览器                     WeKnora 后端                    钉钉
  |  点击「使用钉钉登录」        |                             |
  |--GET /auth/dingtalk/url-->|                             |
  |                           | 生成 nonce，把 {nonce, redirect_uri}
  |                           | 签名进 state，nonce 下发为 HttpOnly cookie
  |<--authorization_url-------|                             |
  |------------ 跳转扫码 -------------------------------->|
  |<--------------- 回调 /auth/dingtalk/callback?code&state --|
  |--GET callback------------>|                             |
  |                           |--POST userAccessToken----->|
  |                           |<--accessToken--------------|
  |                           |--GET contact/users/me----->|
  |                           |<--unionId/nick/avatar------|
  |                           | 解析 unionId → 本地用户      |
  |                           | 签发本地 JWT（与密码登录同构） |
  |<--302 /#oidc_result=...---|                             |
```

回调结果编码进 URL 的 `#oidc_result` 片段，前端复用了 OIDC 的回调解析逻辑，因此不需要为钉钉单独实现一套前端回调。

### 安全设计

- **state 防重放**：`state` 是 HMAC 签名的 `{nonce, redirect_uri, iat}`，10 分钟过期；`nonce` 另外绑定到 HttpOnly cookie，回调时两者必须一致，攻击者无法把自己拿到的 code 塞进受害者浏览器。
- **不动 id_token**：完全不解析、不信任钉钉返回的令牌载荷，只把 `accessToken` 当作访问通讯录接口的凭据。
- **出站请求走 SSRF 安全客户端**：端点同样受 `ValidateURLForSSRF` 约束，30 秒超时。
- **回调接口限流**：`/auth/dingtalk/callback` 挂载与邀请注册相同的按 IP 限流，避免授权码被反复试探。

## 账号映射策略

登录时按以下顺序解析身份（`internal/application/service/dingtalk.go`）：

1. **已有绑定**：`user_identities(provider='dingtalk', provider_subject=unionId)` 命中，直接用对应本地用户。这是首次登录之后的常规路径。
2. **按邮箱绑定**（仅当 `DINGTALK_BIND_BY_EMAIL=true`）：unionId 未绑定时，若钉钉返回的邮箱命中已有本地账号，则把该钉钉身份绑定上去。
3. **按策略开户或拒绝**：
   - `create_personal`：自动建账号并创建个人空间（与公开注册一致）。
   - `tenantless`：只建账号、不建空间，等待邀请后加入空间。**内部部署推荐**。
   - `deny`：拒绝登录，返回 `not_linked`，必须由管理员先行绑定。适合严格白名单。

钉钉企业应用常常不返回邮箱，此时用 `<unionId>@dingtalk.local` 作为占位邮箱，以满足 `users.email` 的非空唯一约束。自动开户的账号会打上 `sso_only_login` 偏好标记，个人资料页据此隐藏「修改密码」，因为该密码是服务端随机生成、用户并不知道。

并发安全：`user_identities` 上的 `UNIQUE(provider, provider_subject)` 保证同一 unionId 只会绑定一个本地账号；两个首登请求竞争时，落败方会重新读取胜出方的绑定，而不是再建一个账号。

## 数据模型

新增表 `user_identities`（迁移：`migrations/versioned/000138`、`migrations/sqlite/000054`）：

| 列 | 说明 |
| --- | --- |
| `user_id` | 本地 `users.id` |
| `provider` | `dingtalk`（预留企业微信、飞书） |
| `provider_subject` | 钉钉 `unionId` |
| `provider_tenant` | 钉钉 CorpId，可空 |
| `display_name` / `avatar_url` | 缓存钉钉资料用于展示 |
| `last_login_at` | 最近一次 SSO 登录时间 |

唯一索引：`(provider, provider_subject)` 与 `(user_id, provider)`，均带 `deleted_at IS NULL` 部分索引。

## 接口

| 方法与路径 | 说明 |
| --- | --- |
| `GET /api/v1/auth/dingtalk/config` | 返回 `{enabled, provider_display_name}`，前端据此决定是否展示入口 |
| `GET /api/v1/auth/dingtalk/url?redirect_uri=` | 返回授权 URL，并把 nonce 写入 HttpOnly cookie |
| `GET /api/v1/auth/dingtalk/start` | 直接 `302` 到钉钉，供企业门户或 IM 工作台放一个链接 |
| `GET /api/v1/auth/dingtalk/callback` | 回调：换取令牌、解析身份、签发本地 JWT |

回调失败时跳转 `#oidc_error=<code>`，其中 `code` 可能是 `invalid_state`、`missing_code`、`not_linked`、`login_failed`。

## 排障

| 现象 | 排查方向 |
| --- | --- |
| 登录页没有钉钉按钮 | `GET /auth/dingtalk/config` 是否返回 `enabled:true`；`app_key`/`app_secret` 是否齐全 |
| 回调报 `invalid_state` | 回调地址与钉钉后台登记的不一致，或超过 10 分钟；确认经反向代理后 `X-Forwarded-Proto`/Host 正确 |
| 提示 `not_linked` | `DINGTALK_PROVISIONING_MODE=deny` 且该 unionId 未绑定；改为 `tenantless` 或先绑定身份 |
| 钉钉侧报 redirect_uri 不匹配 | 检查应用的登录回调白名单是否精确到 `/api/v1/auth/dingtalk/callback` |
| 账号建好了但看不到任何空间 | `tenantless` 模式的预期行为：需要管理员邀请加入空间 |
