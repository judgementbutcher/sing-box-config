# sing-box 配置生成与发布

把一份策略文件和本机订阅，生成 Windows（SFW）与 Android（SFA）两端的 sing-box 配置，经核心校验后在局域网内发布给客户端拉取。不提供面板、统计或核心托管；核心的运行由 SFW / SFA 自己管理。

```
config/policy.yaml ─┐
config/rule-sets/   ├─ generator ─ sing-box check ─ dist/{desktop,android}/config.json ─ publisher ─ SFW / SFA
config/local/（订阅）┘
```

## 日常使用

双击 `scripts\manage\manage.bat`：

| 菜单 | 命令行（`.\scripts\manage\manage.ps1 -Action …`） | 作用 |
| --- | --- | --- |
| 1 更新配置 | `all`（加 `-Offline` 不下载订阅，只用缓存） | 拉取订阅 → 生成两端配置 → 核心校验 → 发布到 `dist` |
| 2 检查 | `check` | 核对 `dist` 里的配置未被改动，并用核心重新校验 |
| 3 添加订阅/节点 | `add -Name 名字 -Link 链接` | 链接可以是订阅地址或单个节点 URI，格式自动识别 |
| 4 删除/停用/启用 | `remove` / `disable` / `enable -Name 名字` | 维护订阅清单 |
| 5 启动发布 | `publisher`（可加 `-AdvertiseHost 192.168.1.31`） | 启动发布器并显示地址和凭据 |
| 6 查看发布信息 | `show-info` | 只显示地址和凭据，不启动服务 |
| 7 轮换凭据 | `rotate-credentials` | 换一组安卓端的访问凭据 |

更新配置的每一步都在临时目录里完成，全部通过才原子替换 `dist`；任何一步失败，`dist` 里仍是上一份可用配置。添加、删除订阅后会立即重新生成，失败则恢复原清单。

运行中的客户端不会自己感知新配置：更新后要在 SFW / SFA 里更新一次配置（profile）。

## 目录

| 路径 | 内容 |
| --- | --- |
| `config\policy.yaml` | 唯一的策略文件，`config` 一节就是最终的 sing-box 配置 |
| `config\rule-sets\*.txt` | 域名名单，一行一个域名后缀 |
| `config\local\` | 本机订阅清单和订阅文件，不进 Git |
| `singbox_config\generator.py` | 生成器 |
| `singbox_config\publisher.py` | 局域网发布器 |
| `parsers\` | sing-box JSON / Clash / 节点 URI 订阅解析 |
| `dist\` | 生成结果和验证标记 |
| `runtime\` | 订阅缓存、校验核心、日志 |

## 改分流

**只想改某个域名的走向**，往名单里加一行，然后更新配置：

| 名单 | 效果 |
| --- | --- |
| `config\rule-sets\direct.txt` | 国内解析 + 直连 |
| `config\rule-sets\proxy.txt` | 代理侧解析 + 走 `Available` |
| `config\rule-sets\block.txt` | 屏蔽（DNS 返回 NXDOMAIN，连接拒绝） |

多数域名不需要写：国内站点由 `geosite-cn` 覆盖，海外站点由 `geosite-geolocation-!cn` 覆盖，两张名单都没收录的域名按解析结果自动判断（见下文 DNS）。

**其他改动**都在 `config\policy.yaml`。它的 `config` 一节按 sing-box 官方配置的结构原样书写，写什么就生成什么。生成器只额外做三件事：

1. **`only: desktop` / `only: android`**：列表里带这个标记的条目只保留在对应平台。
2. **出站**：`outbounds` 不用写，由订阅和 `groups` 生成（见下文）。
3. **规则集**：`route.rule_set` 不用写。规则里引用了哪个名字就自动补哪个——`config\rule-sets` 下有同名 `.txt` 就内嵌，否则按 `rule_set_urls` 里与名字前缀对应的地址远程下载（`geosite-xxx`、`geoip-xxx`）。

DNS 规则和路由规则是成对的：一个名单走哪个出口，就用哪一侧解析（直连 → `domestic`，走代理 → `proxy`，屏蔽 → NXDOMAIN），两边先后顺序也要一致。测试 `test_policy_dns_rules_mirror_route_rules` 会检查这一点，改完跑一遍 `python -m pytest` 就知道有没有漏。

例：新增一个 Netflix 分组，共三行。

```yaml
groups:
  services:
    - {tag: Netflix}                                     # 1. 面板里多一个分组
config:
  dns:
    rules:
      - rule_set: [geosite-youtube, …, geosite-netflix]  # 2. 加进"代理侧解析"那条规则
        server: proxy
  route:
    rules:
      - {rule_set: geosite-netflix, outbound: Netflix}   # 3. 和其他业务分组放在一起
```

### 分组

| 分组 | 成员 |
| --- | --- |
| `Available` | 各订阅（多节点订阅是同名分组，单节点订阅就是节点本身），外加 `Other` |
| `AI` | `groups.ai_regions` 白名单地区的节点，按白名单顺序排列，外加 `Other` |
| `Other` | 名字里识别不出地区的节点；不进业务分组 |
| `groups.services` 里的业务分组 | 默认 `Available` 加各订阅，跟随 `Available` 的当前选择；`direct: first` 把直连放在最前并作为默认（Spotify），`direct: last` 把直连放在末尾（Emby）；`expand: true` 不引用 `Available`，而是展开成它的成员（各订阅分组与 `Other`） |

所有分组都是手动选择器，第一个成员是默认值，选中的节点由 `cache_file` 记住。

## 订阅

清单是 `config\local\subscriptions.yaml`，写法和各字段说明见 [config/examples/subscriptions.yaml](config/examples/subscriptions.yaml)。最简的一条只有两行：

```yaml
subscriptions:
  - name: example
    path: subscriptions/example.url.txt   # 文件里放一行订阅链接
```

- 清单顺序就是面板顺序，第一条是 `Available` 的默认出口。
- `path` 指向的文件如果只有一行 http(s) 链接，就当作订阅地址下载；否则文件本身就是订阅内容。sing-box JSON、Clash YAML、节点 URI 列表（含整体 Base64）自动识别。
- 下载先直连，失败后经 `subscription.retry_proxy` 再试，仍失败就使用 `cache_max_age` 以内的缓存。
- 连接参数完全相同的节点只保留第一个；指向本机或端口无效的占位节点自动丢弃。
- 名字里带"剩余流量""套餐到期""Traffic""Expire"等字样的信息条目会保留，显示在该订阅分组的末尾；它们不是节点（`block` 出站），不进 `AI` 和 `Other`。不想看到的用 `exclude` 排除。
- 关闭了 TLS 证书校验的节点默认直接报错，确认要用再给该订阅加 `allow_insecure: true`。

## DNS

四个 DoH 解析器分成两组，组内并发、先成功的生效（reF1nd 的 `type: group`）：

- `domestic`：AliDNS + DNSPod，直连。用于直连的域名、节点自身的域名。
- `proxy`：Google + Cloudflare，经 `Available` 出去。用于走代理的域名，拿到的是代理出口附近的 CDN 地址。

TUN 是真实 IP 模式：客户端先拿到解析结果再发起连接，所以**被墙域名必须由代理侧解析**，否则连接从一开始就指向污染地址。规则顺序是：

1. 屏蔽名单 → NXDOMAIN。
2. 业务名单、`proxy` 名单 → `proxy`。
3. `direct` 名单、`geosite-cn` → `domestic`。
4. 广告名单 → NXDOMAIN；`geosite-geolocation-!cn` → `proxy`。
5. 以上都没命中的域名：先用 `proxy` 解析；答案落在 `geoip-cn` 里说明是国内站点，改用 `domestic` 的答案（CDN 就近，路由层按 `geoip-cn` 直连）；否则直接采用代理侧的答案。

第 5 步不能反过来用国内解析器的答案做判断，也不能让两组解析器竞速：国内解析器对被墙域名返回得更快，给的是假地址，而假地址偶尔也落在大陆 IP 段内（实测 `annas-archive.org → 118.184.78.78`）。测试 `test_policy_unlisted_names_are_decided_by_the_proxy_side_answer` 和 `test_policy_dns_servers_never_mix_trust_levels` 守着这两点。

另外两处有意的选择：

- 解析器都写 IP、不写 `detour: direct`（核心会拒绝启动），也不用 `type: local`（TUN 把系统 DNS 指向自己，`local` 会查回 sing-box）。
- Spotify 默认直连（`expand: true` 把各订阅分组和 `Other` 展开摆在 `Spotify` 组里，随时可切），解析放在代理侧：`open.spotify.com` 在国内解析器上是被污染的。网页播放器本身直连不通，要用它就把 `Spotify` 分组切到节点。

## 发布

发布器固定监听 TCP `18080`，只提供配置文件：

- 本机 SFW：`http://127.0.0.1:18080/desktop/config.json`
- 其他电脑的 SFW：`http://电脑局域网IP:18080/desktop/config.json`
- Android/SFA：`http://电脑局域网IP:18080/android/config.json`，启动时打印的链接已带访问令牌，直接粘贴进 SFA

安卓端配置需要令牌或 HTTP Basic Auth（凭据在 `.secrets\android-publisher.json`）；桌面端为兼容 SFW 自动更新不要求认证。每次请求都会核对 `config.validated.json` 里的 SHA-256，未经校验或被手工改过的配置不会发布。发布器前台运行，`Ctrl+C` 停止；每个请求和中断都记在 `runtime\publisher.log`（只记路径，不记令牌）。

首次启动时，如果 18080 落在 Windows 保留端口段（WinError 10013）或防火墙未放行，管理脚本会申请管理员权限处理；拒绝的话需要手动放行 Private/Public 网络的 TCP 18080。建议在路由器里给电脑固定局域网 IP。

链接里的局域网 IP 由发布器自动探测（只认默认路由所在网卡，排除环回、链路本地和 TUN 地址段）。探测不到时会打印警告，用 `-AdvertiseHost` 指定。

### 手机拉不到配置

- **`connect: connection timed out`**：先关掉手机的移动数据。Wi-Fi 没通过 Android 联网检测时，系统会把应用的默认网络切到蜂窝，蜂窝上的连接到不了局域网。
- **关 VPN 一直等待、开 VPN 报 EOF**：手机里那条配置的远程地址是旧的 `172.18.0.1`（手机自己 TUN 的地址）。删掉该配置，重新粘贴当前打印的链接，不要只点"更新"。
- **其他 EOF / 连接被重置**：手机上正在生效的旧配置把局域网流量带进了代理。在 SFA 里断开 VPN 后再更新一次；现在的安卓配置已把私有网段排除在 TUN 之外（`route_exclude_address`），更新成功后不会复发。也可以把 `dist\android\config.json` 直接传到手机按本地配置导入。

## 安装与验证

```powershell
.\scripts\bootstrap\setup.bat          # 建 .venv、装依赖、生成一次配置
python -m pytest                        # 单元测试 + policy.yaml 回归检查
python .\scripts\quality\check_public_repo.py   # 确认没有订阅、凭据进入 Git
```

系统 Temp 目录权限异常导致 pytest 报 `PermissionError` 时，加 `--basetemp=runtime\pytest-tmp`。

`sing-box check` 只校验结构，不执行 DNS 规则。动了 DNS 规则之后要真查一遍：起一个不带 TUN 的实例（去掉 TUN 入站，`route.default_interface` 绑物理网卡以绕开正在运行的 TUN，保留 mixed 入站），对比一个名单外的被墙域名（如 `genius.com`）和一个国内域名，确认前者拿到代理侧答案、后者拿到国内答案。

`config\local\`、`.secrets\`、`runtime\`、`dist\`、核心二进制均不进 Git。

## 核心版本

配置面向 **sing-box 1.15 的 reF1nd 分支**，客户端（SFW / SFA）必须使用同一系列的核心：

- 用到的 reF1nd 专有项：DNS 的 `type: group` 服务器、`experimental.urltest_unified_delay`。
- 用到的较新官方项：DNS 规则动作 `evaluate` / `respond` 与 `match_response`（1.14）、顶层 `http_clients`（1.15，远程规则集经代理下载）。
- TUN 不写 `stack`、`mtu`、`udp_timeout`，交给核心默认值。

校验用的 CLI 核心放在 `runtime\cores\<版本>\`，版本由 `scripts\manage\manage.ps1` 里的 `$PreferredCoreVersion` 指定（当前 `1.15.0-alpha.11-reF1nd`，与正在使用的客户端一致，来自 [reF1nd/sing-box-releases](https://github.com/reF1nd/sing-box-releases/releases)），也可以用环境变量 `SING_BOX_CORE` 指向别处。找不到版本一致的核心时，生成和检查都会直接失败，而不是退回 PATH 上任意一个 `sing-box.exe`——SFW 安装目录里那个是 Electron 桩，执行任何命令都静默返回 0。

参考：[sing-box 配置文档](https://sing-box.sagernet.org/configuration/) · [变更日志](https://sing-box.sagernet.org/changelog/)
