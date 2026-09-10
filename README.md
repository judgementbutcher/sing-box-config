# sing-box 配置维护与发布

本项目只做两件事：

1. 维护、生成和校验 Windows SFW 与 Android/SFA 的 sing-box 配置。
2. 在局域网内发布经过校验的配置。

项目不提供网页面板、流量统计、核心托管或开机自启服务。Windows 的 sing-box 核心生命周期由 SFW 管理。

## 日常使用

双击 `scripts\manage\manage.bat`。管理菜单按两类功能组织：

- 配置维护：生成全部配置、只生成桌面/安卓配置、检查已发布配置，维护本机订阅/单节点，以及用编号列表维护分组与域名分流规则。
- 配置发布：启动发布、查看发布信息、轮换发布凭据。

生成流程先写入 `runtime` 临时目录，通过生成器结构检查和可用的 sing-box CLI 核心检查后，再原子替换 `dist` 中的配置与验证戳。失败不会覆盖现有配置。

命令行入口：

```powershell
.\scripts\manage\manage.ps1 -Action all
.\scripts\manage\manage.ps1 -Action desktop
.\scripts\manage\manage.ps1 -Action android
.\scripts\manage\manage.ps1 -Action check
.\scripts\manage\manage.ps1 -Action quick-add -Name "拼车" -Link "https://example.com/subscription"
.\scripts\manage\manage.ps1 -Action disable -Name "provider"
.\scripts\manage\manage.ps1 -Action enable -Name "provider"
.\scripts\manage\manage.ps1 -Action remove -Name "provider"
.\scripts\manage\manage.ps1 -Action publisher
.\scripts\manage\manage.ps1 -Action show-info
.\scripts\manage\manage.ps1 -Action rotate-credentials
```

管理脚本菜单也提供以上操作，以及“快速添加节点/订阅”：输入名称和链接后，脚本会自动识别单节点 URI、URI 订阅、Clash YAML 或 sing-box JSON，保存到 `config\\local`，并立即生成、校验两端配置。订阅类链接在每次执行桌面、安卓或全部更新时重新拉取；运行中的 sing-box 不会自行拉取，必须再次运行更新操作。

选择菜单中的“删除/禁用节点或订阅”后，会列出 `subscriptions.yaml` 中的所有条目，可选择删除、禁用或重新启用；删除本地条目时也会清理其对应的节点文件。

选择“分组与分流规则”后，可以创建或删除 selector 分组，也可以直接粘贴链接、域名、IP 或网段加入任意分组，或快速添加直连规则：

- `[4] 快速添加直连规则`：粘贴要直连的链接/域名/IP，脚本自动识别并路由到 `direct`（DNS 走本地解析），适合“这个站点不走代理”的临时需求。
- `[3] 增加分流规则`：选择目标分组后粘贴同样格式的内容，可走代理或直连。

输入的匹配内容支持以下格式，可一次粘贴多个（用空格或逗号分隔）：

| 输入示例 | 生成规则 |
| --- | --- |
| `https://platform.deepseek.com/usage` | 匹配主机名 `platform.deepseek.com`（含子域名） |
| `deepseek.com` / `*.example.cn` / `sub.example.co.uk` | `domain_suffix`，任意域名格式（`.com/.cn/.io/.dev/.co.uk/…`） |
| `full:docs.deepseek.com` | `domain` 精确匹配，不含子域名 |
| `keyword:cdn` | `domain_keyword` 关键词匹配 |
| `regexp:^ad[0-9]+` | `domain_regex` 正则匹配 |
| `1.2.3.4` / `10.0.0.0/8` / `2001:db8::1` | `ip_cidr`（IPv4/IPv6 及网段，自动补全前缀长度） |

带协议、端口、路径或查询参数的完整链接会自动提取主机名；中文/Unicode 域名会自动转为 punycode。每条规则生成后都会立即重新生成并校验双端配置，失败时自动恢复原配置。数据保存在本机的 `config\local\routing-groups.json`。

也可直接运行 `python -m singbox_config.simple_generator all --offline`（需在项目根目录）；单端目标使用 `desktop` 或 `android`。

## 配置发布

发布器监听 TCP `18080`，只提供以下配置文件和健康检查：

- 同一台 Windows 上的 SFW（首选）：`http://127.0.0.1:18080/desktop/config.json`
- 其他电脑上的 SFW：`http://电脑局域网IP:18080/desktop/config.json`
- Android/SFA：`http://电脑局域网IP:18080/android/config.json`
- 健康检查：`http://电脑局域网IP:18080/healthz`

每次启动发布器都会在终端明确打印两个发布地址、用户名和密码，避免遗忘。`show-info` 可随时再次显示，`rotate-credentials` 会轮换密码并显示新信息。

发布端的 Android 配置使用 HTTP Basic Auth，凭据保存在 `.secrets\android-publisher.json`；桌面 `/desktop/config.json` 为兼容 SFW 自动更新而不要求认证。每次配置请求都会核对相应 `config.validated.json` 的 SHA-256；未校验或被手工改动的配置不会发布。响应禁用缓存，发布器以前台方式运行，按 `Ctrl+C` 停止。

桌面发布产物是自包含的单个 JSON：项目内的本地规则会被内嵌，远程规则不会引用发布电脑上的缓存路径。SFW 与发布器在同一台电脑时请使用 `127.0.0.1` 地址，避免局域网地址被 TUN 或虚拟网卡路由影响。

建议在路由器中为电脑设置 DHCP 地址保留，避免局域网 IP 改变导致远程配置地址失效。如需跨设备访问，还需允许 Windows“专用网络”上的 TCP `18080`。

## 配置结构

- `config\policy.yaml`：公共 DNS、出站选择器、规则集与分流策略。
- `config\rule-sets\`：跨平台共用的规则集合；生成远程配置时自动内嵌。
- `config\profiles\desktop.yaml`：Windows/SFW 专用配置。
- `config\profiles\android.yaml`：Android/SFA 专用配置。
- `config\local\`：本机订阅与自定义规则，不提交 Git。
- `config\local\routing-groups.json`：管理脚本创建的本机分组及其域名分流规则。
- `dist\desktop\config.json`：生成后的桌面配置。
- `dist\android\config.json`：生成后的安卓配置。

订阅清单 `config\local\subscriptions.yaml` 使用严格 schema：

```yaml
schema_version: 1
subscriptions:
  - name: provider
    enabled: true
    format: clash
    source: url_file
    path: subscriptions/provider.txt
    user_agent: sing-box
    group: provider
    order: 100
    urltest: true
    include: [高速, 流媒体]
    exclude: [过期, 套餐]
    max_nodes: 30
    # 默认拒绝 skip-cert-verify/allowInsecure 节点；仅在确认必要时显式开启。
    allow_insecure: false
```

支持 `file` 和 `url_file`；支持 `clash`、`singbox-json` 与 `uri`。默认遇到不支持或字段不完整的节点就终止生成；确需跳过时，仅对相应订阅设置 `allow_unsupported: true`。
默认也会拒绝关闭 TLS 证书校验的节点；只有确认订阅确实需要时，才对该订阅设置 `allow_insecure: true`。
默认会合并连接参数完全相同的节点；如果需要保留订阅中的每个节点名称，可对该订阅设置 `deduplicate: false`。设置 `urltest: false` 时，订阅分组只包含手动选择项，不生成 `/Auto`。

自定义规则 `config\local\custom-rules.yaml` 只接受显式数组：

```yaml
schema_version: 1
route_rules_front: []
route_rules: []
dns_rules: []
rule_sets: []
```

### 手动添加或修改分流规则

规则的公共部分在 `config\policy.yaml`：

- `route.business_rules` 控制连接走向；`outbound: direct` 表示直连，`Available`/`AI`/`Emby` 表示交给对应策略组。
- `dns_rules.business_rules` 控制域名解析使用的 DNS；直连域名通常配 `server: local`，需要代理解析时配 `server: google`。
- 两处规则都按文件中的顺序匹配，越靠前优先级越高。修改后重新生成配置，桌面和 Android 才会生效。

只想为本机临时增加规则时，编辑 `config\local\custom-rules.yaml`（该目录不会提交 Git），将规则分别放入 `route_rules` 和 `dns_rules`；它们会在公共业务规则之前生成。例如：

```yaml
schema_version: 1
route_rules:
  - domain_suffix: [example.com]
    action: route
    outbound: direct
dns_rules:
  - domain_suffix: [example.com]
    action: route
    server: local
route_rules_front: []
rule_sets: []
```

域名规则填写域名本身即可，不要带 `https://`、路径或端口；`domain_suffix` 会同时匹配该域名及其子域名。修改后运行 `scripts\manage\manage.bat` 的生成操作，或执行 `python -m singbox_config.simple_generator all --offline`。

管理脚本维护的分组文件结构如下，`domains` 每一项是 `类型:值` 形式的规范匹配器，直接书写裸域名时按 `domain_suffix` 处理：

```json
{
  "schema_version": 1,
  "groups": [
    {
      "tag": "xxx",
      "outbounds": ["Provider", "direct"],
      "domains": ["domain_suffix:example.com", "full:www.example.com", "keyword:cdn", "ip_cidr:10.0.0.0/8"]
    },
    {
      "tag": "direct",
      "outbounds": [],
      "domains": ["domain_suffix:platform.deepseek.com"]
    }
  ]
}
```

`direct` 分组的域名会同时生成 `server: local` 的 DNS 规则（本地解析，避免代理 DNS 泄漏）；其他分组的 DNS 走 `server: google`。IP/CIDR 规则只参与路由，不参与 DNS。

## 安装与验证

首次安装依赖并生成双端配置：

```powershell
.\scripts\bootstrap\setup.bat
```

自动验证：

```powershell
python -m pytest
python .\scripts\quality\check_public_repo.py
```

`config\local\`、`.secrets\`、`runtime\`、`dist\`、核心二进制和订阅凭据均不得提交。

## 官方参考

- [sing-box 配置文档](https://sing-box.sagernet.org/configuration/)
- [sing-box 变更日志](https://sing-box.sagernet.org/changelog/)
- [1.14.0 GitHub Release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.0)
