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
.\scripts\manage\manage.ps1 -Action publisher -AdvertiseHost 192.168.1.31
.\scripts\manage\manage.ps1 -Action show-info
.\scripts\manage\manage.ps1 -Action rotate-credentials
```

管理脚本菜单也提供以上操作，以及“快速添加节点/订阅”：输入名称和链接后，脚本会自动识别单节点 URI、URI 订阅、Clash YAML 或 sing-box JSON，保存到 `config\\local`，并立即生成、校验两端配置。订阅类链接在每次执行桌面、安卓或全部更新时重新拉取；运行中的 sing-box 不会自行拉取，必须再次运行更新操作。

选择菜单中的“删除/禁用节点或订阅”后，会列出 `subscriptions.yaml` 中的所有条目，可选择删除、禁用或重新启用；删除本地条目时也会清理其对应的节点文件。

选择“分组与分流规则”后，可以创建或删除 selector 分组，也可以直接粘贴链接、域名、IP 或网段加入任意分组，或快速添加直连规则：

- `[4] 快速添加直连规则`：粘贴要直连的链接/域名/IP，脚本自动识别并路由到 `direct`（DNS 走国内直连解析器），适合“这个站点不走代理”的临时需求。
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
- Android/SFA：`http://电脑局域网IP:18080/android/config.json`，启动输出中的链接末尾已附带访问令牌参数，SFA 中直接粘贴即可
- 健康检查：`http://电脑局域网IP:18080/healthz`

每次启动发布器都会在终端明确打印三个发布地址、用户名和密码；Android 链接已附带访问令牌，不需要手工拼接，用户名与密码同时保留输出以便客户端分开填写。`show-info` 会同时探测本机发布服务是否运行；只显示链接不会启动服务。`rotate-credentials` 会轮换密码并显示新信息。请保持“启动发布”的进程运行，手机与电脑连接同一局域网后再导入。

链接里的“电脑局域网IP”由发布器自动探测：只认默认路由所在网卡的地址，并排除环回、`169.254.0.0/16`，以及本次发布配置中 TUN 的地址段（默认 `172.18.0.0/30`）。这一点很关键：本机 sing-box 以服务+TUN 运行（或同时开着 Clash/VMware/Hyper-V 虚拟网卡）时，直接用 UDP 探测拿到的"本机地址"其实是 TUN 地址，而 `172.18.0.1` 正是手机 SFA 自己 TUN 的地址——链接发出去后手机连的是它自己的虚拟网卡，SFA 只会报 EOF 或连接被重置。探测失败时发布器不再猜测，改为打印警告并使用占位地址，此时用 `-AdvertiseHost` 显式指定，例如：

```powershell
.\scripts\manage\manage.ps1 -Action publisher -AdvertiseHost 192.168.1.31
```

发布端的 Android 配置接受链接令牌或 HTTP Basic Auth，凭据保存在 `.secrets\android-publisher.json`；桌面 `/desktop/config.json` 为兼容 SFW 自动更新而不要求认证。每次配置请求都会核对相应 `config.validated.json` 的 SHA-256；未校验或被手工改动的配置不会发布。响应禁用缓存，发布器以前台方式运行，按 `Ctrl+C` 停止。

发布器把每个请求和每个中断都写进 `runtime\publisher.log`（只记路径，不记令牌，超过 1 MB 自动清空），并在启动时打印该路径。手机到底有没有连上来、连上后是成功还是被中断，看这个文件即可：只有本机地址的记录说明手机根本没发出请求（多半是走代理了），出现 `未发送请求即断开` 说明手机连上了但中途放弃。

**手机连上了 Wi-Fi 却报 `connect: connection timed out`。** 先把手机的**移动数据关掉**再试。同时开着移动数据时，如果这个 Wi-Fi 没通过 Android 的联网检测（国内 `connectivitycheck.gstatic.com` 不可达，很常见），系统会把应用的默认网络切到蜂窝，而 Android 按网络隔离路由：绑在蜂窝上的 socket 到不了 Wi-Fi 后面的局域网，表现就是局域网地址连不上、`connect: connection timed out`，而同一台手机的浏览器（默认网络为 Wi-Fi 时）却能打开。手机能回应电脑发来的 ping、但自己发不出去，也是这个原因。处理办法：关掉移动数据（或飞行模式后只开 Wi-Fi）完成导入；长期则在手机设置里关掉"自动切换移动数据 / Wi-Fi 助手"，或把该 Wi-Fi 设为始终连接。

**SFA 报 EOF / 连接被重置时怎么办。** 先看手机上那个配置的**远程地址**是不是上一次打印的链接：发布器曾经会把 TUN 地址（`172.18.0.1`，也就是手机自己 TUN 的地址）印进链接，手机里残留这版地址时特征非常固定——**关掉 VPN 就一直无响应等待，开着 VPN 就报 EOF**（关 VPN 时该地址没有路由，交给默认网关被丢弃；开 VPN 时请求被手机自己的 TUN 接住再丢弃）。遇到这个特征，编辑或删除该配置、重新粘贴当前打印的链接即可，不要只点"更新"。

排除地址过期后仍失败，才是"手机开着 VPN 时自己的拉取被代理带走"：只要手机当前生效的配置把"到局域网"的流量交给了代理，请求就永远到不了电脑。打破死循环有两条路：

1. 在 SFA 里先断开 VPN，再导入或刷新发布链接，成功一次之后新配置会接管——`config\profiles\android.yaml` 已把 `10.0.0.0/8`、`169.254.0.0/16`、`192.168.0.0/16`、`fc00::/7` 和 `fe80::/10` 排除在 TUN 路由之外，局域网及链路本地流量不再进入 sing-box，这类问题不会复发。
2. 直接把 `dist\android\config.json` 传到手机，按本地配置导入（一次性，不带自动更新）。

桌面发布产物是自包含的单个 JSON：项目内的本地规则会被内嵌，远程规则不会引用发布电脑上的缓存路径。SFW 与发布器在同一台电脑时请使用 `127.0.0.1` 地址，避免局域网地址被 TUN 或虚拟网卡路由影响。

建议在路由器中为电脑设置 DHCP 地址保留，避免局域网 IP 改变导致远程配置地址失效。启动发布器时管理脚本会请求管理员权限，自动允许 Windows Private/Public 网络的 TCP `18080`；若拒绝提权，请手动放行该端口。

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
    # 保留原节点名并在生成时展开；设置 true 才使用 fork Provider。
    provider: false
    user_agent: sing-box
    group: provider
    order: 100
    include: [高速, 流媒体]
    exclude: [过期, 套餐]
    max_nodes: 30
    # 默认拒绝 skip-cert-verify/allowInsecure 节点；仅在确认必要时显式开启。
    allow_insecure: false
    # 上游混入本核心加载不了的 outbound 类型时按类型跳过，见下方说明。
    exclude_types: [hysteria, wireguard, shadowsocks]
```

支持 `file` 和 `url_file`；支持 `clash`、`singbox-json` 与 `uri`。默认遇到不支持或字段不完整的节点就终止生成；确需跳过时，仅对相应订阅设置 `allow_unsupported: true`。
`url_file` 订阅默认建议显式设置 `provider: false`，这样客户端显示原始节点名且每个机场分组只包含自己的节点；`provider: true` 会启用 fork 的运行时更新，但节点会显示为 `provider-tag/原节点名`，且不能使用 `max_nodes` 或 `exclude_types`。
默认也会拒绝关闭 TLS 证书校验的节点；只有确认订阅确实需要时，才对该订阅设置 `allow_insecure: true`。
`exclude_types` 按 outbound `type` 跳过节点，被跳过的类型和数量会在生成时打印。免费节点池常混入本核心加载不了的写法（hysteria v1 的 `up`/`down`、wireguard 的旧 `server` 字段、shadowsocks 的 `plugin_opts` 对象），这些节点留在配置里会让 `sing-box check` 直接 FATAL、连带双端生成一起失败。用类型而不是 `exclude_node_tags` 排除：轮换池的节点名每轮都在变，按名字排除必然漏。
默认会合并连接参数完全相同的节点；如果需要保留订阅中的每个节点名称，可对该订阅设置 `deduplicate: false`。订阅分组一律是手动选择器，不生成自动测速分组；旧的 `urltest` 清单字段已移除，再写入会被按未知旧字段拒绝。

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

- `route.business_rules`/`route.domestic_rules` 控制连接走向，按文件顺序匹配，越靠前优先级越高；`outbound: direct` 表示直连，其余值表示交给对应策略组。
- 业务策略组在 `selectors.groups` 中声明（当前 `Emby`/`YouTube`/`Spotify`/`Telegram`/`Twitch`/`Google Play`）：成员是 `Available` 及其全部条目，默认跟随 `Available`，可以在面板里单独指定节点而不影响其他流量。`direct: last` 在成员末尾追加直连（Emby），`direct: default` 默认直连（Spotify，账号地区校验拒绝机房出口）；`when_referenced: true` 的分组只在 profile 规则引用时生成（`Google Play` 只出现在安卓端）。`AI` 组的成员由 `selectors.ai_regions` 白名单决定（当前 US/JP/SG/TW，香港等被上游封锁的地区不会进入）。
- DNS 规则不再单独书写，而是由路由规则自动推导：含域名匹配（`domain*`/`rule_set`）的 `route` 规则使用与出口相同的解析器（`direct` → 国内 DoH，`AI`/`YouTube`/`Twitch` → 经该分组出站的专用 DoH，其余 → 经 `Available` 的 DoH），`reject` 规则返回 NXDOMAIN。规则上写 `dns: <解析器>` 可覆盖（Spotify 固定国内解析），写 `dns: false` 不生成 DNS 规则（`geoip-cn` 这类 IP 规则集）。
- `dns_upstreams` 声明 DoH 解析器模板：`domestic` 为直连的 AliDNS/DNSPod，`proxy` 为 Google/Cloudflare，按 `proxy_detours` 为每个出口展开一组（例如 `google-youtube`/`cloudflare-youtube` 经 `YouTube` 出站，Google 按解析出口分配视频边缘，解析与播放必须同一出口）。
- 同组解析器并行竞速；相邻且解析器相同的规则合并成一个竞速块（`evaluate` ×2 → `respond NOERROR` ×2 → `respond NXDOMAIN` ×2 → `SERVFAIL`）。成功响应竞速返回，NXDOMAIN 要等两路成功响应都未返回后再接受。只合并相邻规则，所以 `policy.yaml` 里把同出口的规则排在一起即可减少生成的规则数。
- 未命中任何规则的域名由 `dns.final`（Google/Cloudflare 经 `Available`）竞速解析，不向国内解析器发送未知域名；双路失败时返回 `SERVFAIL`。
- 国内分流先匹配 `china-direct`、`.cn`/`.中国` 后缀和 `geosite-cn`，再做广告拦截，最后匹配 `geosite-geolocation-!cn`；新注册的中国域名即使暂未进入规则集也会直连并使用国内 DNS。广告拦截排在业务与国内直连规则之后，上游广告名单误收的服务域名会先被放行。
- Windows TUN 使用 `strict_route` + `dns_mode: hijack`，拦截系统 DNS；不再把整张 `geoip-cn` 地址表排除在 TUN 外，以免某些中国 IP 上的代理分组流量绕过规则，同时减少大量静态路由。TUN 自身网关地址在 DNS 劫持之后拒绝非 DNS 流量，避免直连回环。
- 修改后重新生成配置，桌面和 Android 才会生效。

只想为本机临时增加规则时，编辑 `config\local\custom-rules.yaml`（该目录不会提交 Git），将规则分别放入 `route_rules` 和 `dns_rules`；它们会在公共业务规则之前生成。本机自定义规则不做 DNS 自动推导，需要成对书写。例如：

```yaml
schema_version: 1
route_rules:
  - domain_suffix: [example.com]
    action: route
    outbound: direct
dns_rules:
  - domain_suffix: [example.com]
    action: route
    server: domestic
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

分组规则同样按上文的出口规则推导 DNS：`direct` 分组的域名走国内直连解析（避免代理 DNS 泄漏），`AI` 等有专用解析器的分组走该分组出口，其他分组走 `Available` 出口的解析器。IP/CIDR 规则只参与路由，不参与 DNS。

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

若系统 Temp 目录权限异常导致 pytest 报 `PermissionError`，改用项目内临时目录：`python -m pytest --basetemp=runtime\pytest`。

`config\local\`、`.secrets\`、`runtime\`、`dist\`、核心二进制和订阅凭据均不得提交。

## sing-box 1.15 要求

生成的配置面向 sing-box 1.15 预发布系列。Windows Provider 配置锁定 `1.15.0-alpha.9-reF1nd`；Windows SFW 与 CLI 校验核心应使用 [reF1nd/sing-box-releases](https://github.com/reF1nd/sing-box-releases/releases/tag/v1.15.0-alpha.9-reF1nd) 的兼容版本。桌面端 SFW 与安卓端 SFA 必须使用支持下列字段的 1.15 版本核心才能加载对应配置：

- TUN 不再写 `stack`，由 sing-tun 1.15 自带的 TCP/IP 栈接管；该选项已弃用并将在 1.17 删除，生成器审计会拒绝再次出现。
- 配置使用 reF1nd 的 1.15 字段（包括内置 TUN 栈和统一测速延迟），必须由 `1.15.0-alpha.9-reF1nd` 或兼容的下游核心加载；原版核心和 1.14 系列不支持这些字段。只有订阅清单显式设置 `provider: true` 时才会使用 fork 的 Provider 字段。
- 安卓 `auto_redirect` 在 1.15 已完整支持，但需要 root；`config\profiles\android.yaml` 中留有注释掉的开关，已 root 的设备可自行打开。
- 安卓 TUN 仅声明 IPv4 地址（172.18.0.1/30）：全局 IPv6 不进入 sing-box，`ip_version: 6 → reject` 只在桌面生效。这是有意取舍——`strategy: ipv4_only` 下应用几乎拿不到 IPv6 目标，仅硬编码 IPv6 字面量的流量会绕过代理（暴露面很小），换来挂 VPN 时手机仍能访问 IPv6 资源；如需与桌面一致，在 android.yaml 的 TUN 地址中追加 IPv6 即可，细节见该文件注释。
- 1.15.0-alpha.7 新增的 MASQUE/HTTP3 代理、alpha.5 的 Tailcat，以及 alpha.8 的 `dns_server_address`/`dns_search_domain` 规则匹配，只有在配置了对应协议入口或需要按 DHCP/VPN DNS 地址分流时才有作用；当前配置使用普通节点、TUN DNS 劫持和固定 DoH，不启用这些无关选项。
- 当前 `config\local\subscriptions.yaml` 的订阅使用 `provider: false`，生成器在发布时静态展开节点并保留机场原始名称；`Available` 是可手动切换的 selector，机场分组只包含自己的节点，自建 `Meow-US` 不会作为机场后备混入。需要运行时更新时可对单个订阅设置 `provider: true`，但 fork 会显示 `provider-tag/原节点名`。
- `runtime\cores\1.15.0-alpha.9-reF1nd\` 下的 `sing-box.exe` 是 CLI 校验核心，不是 SFW 桌面客户端。当前 CLI zip 为 `sing-box-1.15.0-alpha.9-reF1nd-windows-amd64.zip`，SHA-256：`d1523ddc054c2e27eb88dc5f1b6f8ef50d44de16a4d25ce0e8027dae7377a75e`。管理脚本优先使用版本目录中的 CLI 核心校验。
- `experimental.urltest_unified_delay: true` 启用下游的二次请求测速，减少首次建连和 TLS 握手对延迟结果的影响。
- `experimental.cache_file.store_dns: true` 持久化 DNS 缓存；`flush_interval: 1m` 控制 1.15 写缓冲的落盘间隔。
- `dns.min_cache_ttl: 60` 是 reF1nd 的缓存 TTL 下限：CDN 常见的 10–30 秒 TTL 会让同一域名反复发起两路代理 DoH 竞速，抬到 60 秒后显著减少重复查询。

## 官方参考

- [sing-box 配置文档](https://sing-box.sagernet.org/configuration/)
- [sing-box 变更日志](https://sing-box.sagernet.org/changelog/)
- [1.15 迁移说明：TUN stack](https://sing-box.sagernet.org/migration/#migrate-tun-stack)
- [sing-box GitHub Releases](https://github.com/SagerNet/sing-box/releases)
