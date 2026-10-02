# nwctl — NodeWarden 运维 CLI

`nwctl` 管理实例运维信息，**不是密码库客户端**。密码库条目、解密与同步仍使用官方 Bitwarden `bw`。本包属于 Fork 的独立工具。0.3.0 新增精确设备管理、邀请管理，以及网页一次性授权后的备份运行、远端下载与校验。不会部署 Worker、修改备份配置、删除远端文件或用户。密码库和 R2 附件不迁移。

## 安装

要求 Node.js **22.12+**。本次生产支持平台为 Linux；macOS 的双行粘贴登录在 CI 中仍超时，尚未完成验收，Windows 未验证。仓库源码安装不需要根目录依赖：

```sh
cd tools/nwctl
npm ci
npm run build
node bin/nwctl.mjs --help
npm pack
```

将生成的 `nodewarden-ops-cli-0.3.0.tgz` 带到任何有 Node.js 的干净目录：

```sh
npm install /absolute/path/nodewarden-ops-cli-0.3.0.tgz
./node_modules/.bin/nwctl --version
```

`private: true` 防止意外 npm publish。本包不公开发布 npm；运维可显式执行 `npm install --global /absolute/path/nodewarden-ops-cli-0.3.0.tgz` 安装到服务器。Commander 随构建产物打包，运行包无 npm 运行时依赖，可在空 npm 缓存下离线安装。运行包仅包含 CLI、文档及许可；测试 Worker、数据库工具和源码不会进入包。

## 开始使用

以下命令假定 `nwctl` 已在 PATH（或替换为 `node bin/nwctl.mjs`）：

```sh
nwctl profile add prod --server https://nodewarden.865455.xyz
nwctl profile use prod
nwctl doctor
nwctl auth login --apikey
nwctl whoami
nwctl backup destinations list
nwctl backup status
nwctl backup status --check --max-age 48h
nwctl backup remote list --destination DESTINATION_ID
nwctl backup remote list --destination DESTINATION_ID --path attachments
nwctl users list
nwctl audit list --limit 50 --offset 0
nwctl auth status
nwctl auth logout
```

在受控本地终端输入个人 `client_id` 与 `client_secret`，**两项均隐藏输入**。不要把 Secret、主密码或 Token 贴进聊天或写在命令行参数。CLI 不获取 API Key、不创建 Key、不请求主密码。非 TTY 默认拒绝登录；确需受控管道时使用 `auth login --apikey --credentials-stdin`，stdin 必须是客户端 ID 与 API Secret 两行，由安全凭据工具提供，不能在 shell 历史里写明文。

## 0.3.0：网页操作进入 CLI

```sh
nwctl devices show DEVICE_ID
nwctl devices rename DEVICE_ID --name 手机 --dry-run
nwctl devices rename DEVICE_ID --name 手机 --yes
nwctl devices revoke-trust DEVICE_ID --yes
nwctl devices remove DEVICE_ID --yes
nwctl invites list
nwctl invites create --expires 24h --output /私有目录/invite.json --yes
nwctl invites revoke INVITE_REFERENCE --yes
nwctl backup run --destination DESTINATION_ID --dry-run
nwctl backup run --destination DESTINATION_ID --yes
nwctl backup remote download --destination DESTINATION_ID --path EXACT_FILE.zip --output /私有目录/backup.zip --yes
nwctl backup remote verify --destination DESTINATION_ID --path EXACT_FILE.zip --yes
nwctl users show USER_ID
nwctl audit settings show
```

**普通设备操作**支持 `--dry-run` 和明确确认；`--yes` 仅跳过本地确认。只管理自己的设备，当前 CLI 设备仍用 `auth logout --server`。取消信任只撤销记住二次验证，不会踢下线；移除设备后的跨实例鉴权缓存最长可能滞后 15 秒。

**邀请/备份**命令只创建待确认请求，尚未执行目标操作：

1. 打开返回的本站 `/cli-approval/UUID` 链接，在可信浏览器登录同一管理员账号，核对实例、动作、目标、参数和副作用，再用主密码确认。
2. 返回 CLI：`nwctl ops status REQUEST_ID`，再执行 `nwctl ops execute REQUEST_ID --yes`。也可用 `nwctl ops cancel REQUEST_ID --yes` 取消。
3. 请求最多有效 10 分钟；批准后最多 2 分钟内开始执行，且不能晚于原登录会话到期。服务端绑定账号、实例、原 CLI token/设备、动作和参数；再次登录后旧请求不能执行。
4. 链接只含非授权凭据的请求 ID；另一个 0600 本地文件保存随机单次 proof，服务器仅保存 SHA-256。主密码/hash 不进入 CLI 或本地配置。授权页目前支持 PBKDF2 主密码验证，不冒用备份修复的 Passkey 票据。
5. 原子状态机保证一个请求最多尝试执行一次，不承诺网络故障下 exactly-once 成功。`executing/unknown/failed` 不自动重放；检查 `ops status` 和真实目标后再决定。写入 HTTP 5xx、超时或连接中断都不能解释为“未发生修改”。

邀请列表只输出邀请码 SHA-256 引用；创建出的秘密链接只写入显式指定的 0600 文件，拒绝覆盖或符号链接。输出父目录必须属于当前用户且不能被组/其他用户写入。

**立即备份会按已有保留策略删除旧档**，CLI 和网页都提示该风险，不改变策略。完成后核对目标运行状态与精确远端档案的名称、大小。生产验收不自动运行备份或移除用户设备。

下载采用私有临时文件、流式大小/时限限制、ZIP 魔数/传输长度检查、同目录原子发布及完整本地 SHA-256 回读。**没有解压或恢复**，ZIP 可能仍引用远端独立附件 blob，不能当作完整附件导出。远端 `verify` 只检查文件名里的 5 位十六进制校验前缀；缺失/不匹配退出 7，永不表示可恢复或有可信完整签名。

需要配套 0.3.0 Worker/Web 部署；只有 CLI 升级而服务端没有 `/api/ops/requests` 时会失败，不降级绕过授权。

## 0.2.0：日常运维与会话管理

```sh
# 复用经过服务端核验的会话；没有或过期时才提示输入 API Key
nwctl --profile prod auth ensure
# 本机显式使用已批准的 root 私有凭据缓存
nwctl --profile prod auth ensure --cached
# 一屏总览，--check 用于定时巡检退出码
nwctl --profile prod status
nwctl --profile prod status --check --max-age 48h
nwctl --profile prod devices list
# 只撤销本 profile 的 CLI 设备，不影响手机/浏览器等其他设备
nwctl --profile prod --timeout 30000 auth logout --server
# 审计筛选仍只读取一个分页，不承诺全量导出
nwctl --profile prod audit list --category device --level security --query device.delete
nwctl --profile prod audit list --from 2026-10-01T00:00:00+08:00 --to 2026-10-02T00:00:00+08:00
```

- `auth ensure --credentials-stdin` 支持受控两行输入；已存在有效会话时复用，不自动换账号。不在后台续期；权限不足、网络或契约错误不会触发自动重登。需要切换账号时显式执行 `auth login`。
- `--cached` 是本服务器的显式集成：仅允许默认 `/home/hermes/.config/nwctl` 下的 `prod` profile、精确生产 origin，通过 `/usr/bin/sudo -n /usr/local/sbin/nwctl-prod-login` 读取已有 root 私有缓存。不会放宽凭据文件权限、复制长期 Key 到 CLI 配置、查询 D1 取 Key，或执行 profile 提供的任意命令。该 helper 必须由管理员独立部署；其他主机使用交互/受控 stdin，不会自动寻找密钥。`--cached` 不能和 `--credentials-stdin` 同用。
- 缓存 helper 超时上限独立为 180 秒；`--timeout` 限制每个 HTTP 请求，以及服务端退出后的验证阶段，不是整条复合命令的总时长。helper 输出不直接透传，CLI 会重新向服务端核验保存的会话。
- `status` 展示实例、API、身份、会话剩余秒数、用户数和备份概况。未登录或普通用户时管理数据为 unknown/null，不能视为健康；网络/契约错误明确失败。`--check` 仅在有效管理员会话且全部目标满足新鲜度条件时通过，否则退出 7。健康只表示这些观测条件，不证明备份能恢复或数据库/Cloudflare 全面正常。
- `devices list` 仅显示本账号的设备 ID、名称、类型、创建/活动时间、信任标记和 `current`；不输出设备包装密钥。
- `auth logout --server` 要求当前有效、设备绑定匹配的会话，不接受设备 ID 或全设备参数。对唯一目标发出一次 DELETE 后，用旧 access token 探测 `/api/accounts/profile`，观察到 401 才报告 `oldAccessRejected: true`。后端跨实例缓存可能短暂滞后；可提高 `--timeout`，但不能把单路径验证说成全球所有节点同步失效。DELETE 一旦发出，无论成功、超时或回包不兼容都会清除本地会话；不会自动重试 DELETE。若删除/验证失败，退出非零且不声称服务端撤销成功。API Key 本身不变，其他设备不变；同 profile 的其他 CLI 进程可能同时被退出。
- 普通 `auth logout` 仍只清本地文件。如果令牌已过期/会话已丢失，不能凭本地设备名做未经验证的删除；通过可信网页客户端管理设备。
- 审计支持 `--category`、`--level`、`--query`、`--from`、`--to`；时间必须包含秒数和明确时区，校验真实日期和起止顺序后转为 UTC 毫秒格式发送。类别/级别为小写标识符（最多 64 字符），关键词 1–512 字符且无控制符，不要在关键词中传秘密。仍保留 `--limit`、`--offset` 和 metadata 脱敏边界；分页在活跃日志下可能变化，不是稳定快照。

## 安全和权限边界

- 查询命令只读 **不等于服务端只读授权**。个人 API Key 和 access token 代表原账号权限；管理员 Token 被盗仍有风险。不要默认交给 Agent 或长驻脚本。
- 登录显式使用 `grant_type=client_credentials`、`scope=api`，稳定的专属 `nwctl` device identifier。后端回包有刷新令牌/包装密钥，但 CLI 不保存或输出它们；refresh token 在保存会话前撤销，撤销失败不保存会话。隔离 E2E 验证旧 refresh token 无法续期且 access token 仍可用。
- 仅保存带到期时间的 access token，不保存 Secret、refresh token、主密码或 masterPasswordHash。过期或 HTTP 401 要重新登录，无后台续期。`auth status` 有会话时执行真实 profile 校验。
- `~/.config/nwctl/config.json` 和独立 `session-NAME.json`：目录 0700，文件 0600，当前用户所有，拒绝符号链接，同目录原子写入。**文件权限保护不是加密保险库**。`--config-dir` 可换私有目录。
- 会话绑定 profile 名称、实例精确 origin 和设备。用 `profile add` 更新地址会先删除旧会话；没有临时 `--server` 转发 Token 的能力。
- 只允许 HTTPS，使用系统 TLS 校验，拒绝请求重定向；没有 `--insecure`。本地测试仅能显式 `--allow-loopback-http` 用 `127.0.0.1` 或 `[::1]`，不能放宽生产。
- `auth logout` 仅删除本地会话，**不立即使已签发 access token 失效**。若疑似泄漏，应在可信客户端撤销专属设备/会话。
- 所有管理查询由后端验证 active/admin。普通用户返回退出码 4，不自动提权。
- 白名单输出身份/备份信息；不输出目标凭据、任意 metadata 或服务器原始错误。审计 metadata 和备份错误正文故意省略，可到可信 Web UI 查详情。Token/已知秘密/常见凭据格式及终端控制字符过滤同时作用于 JSON 输出。
- “业务只读”并非完全不写数据库：认证、设备、审计、限流、后端已有的配置初始化/迁移可能写入运行状态；测试单独比较密码库、备份配置/计划和对象。

## 输出、检查与故障

全局参数可放在子命令前后：`--profile NAME`、`--json`、`--config-dir DIR`、`--timeout MS`（50–120000，默认 15000）。不接受任意 API 请求；仅开放已实现操作的 method/path 白名单。`ops execute --operation-timeout MS` 独立控制执行/传输时限（1000–900000，默认 120000），普通查询仍用全局 timeout。

JSON stdout 只有一个文档：`schemaVersion: 1`、`ok`、`command`、`profile`、`data`、`warnings`；错误使用 `error.code/message/exitCode/httpStatus`。提示走 stderr。分页返回 `items/count/total/limit/offset/hasMore`；`count` 是本页数量，不是所有日志。远端 list 只浏览指定目录；下载/校验必须显式调用对应命令并完成网页授权。

`doctor` 分开显示 CLI 版本和 Bitwarden `compatibilityVersion`；未证明的 NodeWarden 版本与部署 SHA 显示 `unknown`。它不是恢复、数据库或 Cloudflare 全面巡检。

`backup status` 保留各目标计划、时区、ISO 时间及大小：
- `disabled`：计划未启用。
- `never-succeeded`：从未成功。
- `failed`：错误不早于最近成功。
- `stale`：启用目标的成功时间超过阈值。
- `unknown`：时间无效或位于未来。
- `healthy`：其余有效、启用且在阈值内的目标。

空目标、禁用、未知、从未成功都不算 healthy；只有全部目标 healthy 才通过严格检查。`--max-age` 支持整数 m/h/d（1 分钟–365 天），默认 48h；普通 status 只展示信息，只有显式 `--check` 返回 7。此时 JSON 仍是成功查询 (`ok: true`) 且 `data.healthy: false`。

退出码：0 成功；2 参数/不安全存储；3 未登录/过期/认证被拒；4 权限不足；5 网络/TLS/超时/服务端错误；6 响应不兼容或 HTTP 409 业务冲突；7 健康或远端完整性检查未通过/无法验证；130 中断。

GET 最多重试一次（429、502/503/504），尊重 Retry-After 且等待不超过 2 秒、总请求不超过 timeout；POST/PUT/DELETE 不自动重试。JSON 响应上限 2 MiB，明确授权的 ZIP 下载上限 64 MiB。HTML 登录页、不兼容字段和跨 origin 跳转明确失败，不伪造空列表。

## 开发和验证

真实 PTY 回归测试还需要 Python 3（Linux/macOS 标准库 `pty`/`termios`）；CLI 运行时不需要 Python。测试临时目录显式解析到真实路径，以兼容 macOS `/var` 等系统路径别名，同时不放宽正式配置的符号链接拒绝规则。

```sh
npm ci
npm run build
npm run typecheck
npm test
# 以下测试需要仓库根已有 Worker 依赖，根目录先执行 npm ci --ignore-scripts
npm run test:e2e
# 需要 Chromium / Google Chrome，可用 NWCTL_CHROMIUM 指定路径
npm run test:browser
npm pack --dry-run
```

E2E 在真实 Miniflare/workerd 下运行当前 Worker，通过真实 CLI 子进程访问 HTTP，D1/R2/KV 全部隔离且没有 remote binding/CF 凭据。WebDAV、S3 和 Bitwarden 安装接口仅使用明确的 provider fixture，禁止外网连接；不能把测试目录和数据当作生产核验。测试专用路由只出现在内存里的 Worker 测试入口，既不修改生产 src，也不进入 tgz。

CI 只保留一条 Linux 验证：在 `main` 源码推送、面向 `main` 的 PR 或手动触发时执行 Worker 安全/兼容性回归、CLI 类型检查、单元测试、真实 Worker E2E、依赖审计和干净目录安装。`production` 的部署由 Cloudflare Workers Builds 负责，不另用 GitHub Actions 重复部署；生产 PR 和生产分支推送不重复触发 CLI 构建。第一版兼容基线是 Fork `a72592e` 的 NodeWarden 1.8.0；未知新类型/契约变化会报错，而不是猜测兼容。源代码和许可证位于本仓库 `tools/nwctl`；Commander 的 MIT 许可见 `THIRD_PARTY_NOTICES`。

## 明确不包含

备份设置修改、远端删除/恢复、完整附件导出、用户写操作、密码库解密、API Key 创建/轮换、生产部署命令、R2 迁移及无人值守二验授权。不实现全量审计导出或自动定时任务。Passkey 二次确认不包含在首版；必须在网页输入主密码，未知 KDF 明确拒绝。
