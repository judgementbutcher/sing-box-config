# sing-box 配置生成与发布

当前使用方式以本 README 和[文档导航](docs/README.md)中的现行指南为准。项目采用静态配置生成、完整 release 校验和局域网发布；客户端核心由 SFW / SFA 自行管理。

**发布真源是不可变 release，不是 `dist`。** 两端配置、核心校验标记、输入和订阅缓存一起保存到 `runtime/releases/<build_id>`；全部验证后原子切换 `runtime/active-release.json`。`dist` 是供手动导入的兼容导出。客户端实际业务仍需设备端验收。

把一份策略文件和本机订阅，生成 Windows（SFW）与 Android（SFA）两端的 sing-box 配置，经核心校验后在局域网内发布给客户端拉取。不提供面板、统计或核心托管；核心的运行由 SFW / SFA 自己管理。

```
config/policy.yaml ─┐
config/rule-sets/   ├─ release_manager ─ generator ─ sing-box check ─ release ─ active pointer ─ publisher ─ SFW / SFA
config/local/（订阅）┘
```

## 日常使用

双击 `scripts\manage\manage.bat`。首页先只读显示活动版本、工作配置是否有改动、导出同步、订阅和核心状态；不会打开菜单就更新配置或修复文件。

| 菜单 | 内容 | 作用 |
| --- | --- | --- |
| 1 更新配置 | 在线 / 离线 | 展示影响、确认后生成两端配置，核心校验通过才整版激活并导出 |
| 2 订阅管理 | 编号选来源；添加 / 删除 / 停用 / 启用 | 显示启停、活动快照节点数、缓存状态与必需分组依赖；维护会立即生成发布，不是草稿 |
| 3 分流检查 | 域名解释 / 规则结构检查 | 只读解释规则候选与重叠，不查询实际出口、不自动改规则 |
| 4 发布与导入 | 前台启动 / 显示导入信息 / 轮换凭据 | 启动默认隐藏令牌；查看导入信息或轮换完成时展示完整链接，注意屏幕隐私 |
| 5 历史与回退 | 编号选版本 | 显示当前/历史及有效性，确认后复制到新版本、校验并激活 |
| 6 诊断与修复 | 只读诊断 / 完整检查 / 完成同步恢复 | 将查看状态和可能写文件的检查、修复明确分开 |

输入 `0` 或 `q` 退出；`h` 查看帮助。菜单修改操作需输入 `y` 确认，回车取消。发布器保持前台运行，继续管理请另开一个菜单窗口；`Ctrl+C` 停止发布。

### 命令行与自动化

旧的 `-Action all/check/add/remove/disable/enable/rollback/recover/publisher/show-info/rotate-credentials` 入口保留；参数齐全的显式命令直接执行，不追加菜单确认。自动化请加 `-NonInteractive`，避免缺少参数时等待输入。

```powershell
.\scripts\manage\manage.ps1 -Action status                  # 只读状态
.\scripts\manage\manage.ps1 -Action sources                 # 来源、缓存与依赖
.\scripts\manage\manage.ps1 -Action history                 # 历史版本，只读
.\scripts\manage\manage.ps1 -Action explain -Domain claude.ai -Platform android
.\scripts\manage\manage.ps1 -Action lint                    # 静态引用与名单重叠
.\scripts\manage\manage.ps1 -Action status -Json -NonInteractive
.\scripts\manage\manage.ps1 -Action all -NonInteractive     # 在线生成并发布
.\scripts\manage\manage.ps1 -Action all -Offline -NonInteractive
.\scripts\manage\manage.ps1 -Action recover -NonInteractive # 显式修复，可能写文件
```

`status` 只读显示状态；`doctor` 组合只读状态和结构检查。`check` **不是只读**，会先尝试恢复待完成事务，再核对活动版本、固定核心与导出。只读命令不下载订阅、不开核心、不探测发布器；因此服务在线状态和客户端当前选择明确显示未知。域名解释优先使用完整性验证通过的活动版本，不能读取时明确降级到工作策略；缺少协议、IP、包名等运行信息时给出条件候选，不能当作实际命中或业务连通性证明。`lint` 中的跨名单重叠可能是有意设计，不会自动删除。

退出码：`0` 成功，`1` 操作失败，`2` 参数错误，`10` 活动版本已经提交但同步未完成。退出码 `10` 应先恢复，不要盲目重新更新；详细结果会区分提交与同步阶段。

`-ConfigRoot/-RuntimeRoot/-OutputRoot` 可用于隔离查询和发布事务；自定义根目录时，管理入口拒绝 `publisher/show-info/rotate-credentials`，防止误用正式凭据和日志。脚本意外中断后，先看 `status`，如有待恢复事务再执行 `recover`；不能仅凭窗口关闭就认定没有提交。

生成、维护和回退共用跨进程锁。添加、删除、启停先修改候选 YAML；生成或核心检查失败时，活动版本、工作清单与正式缓存均不改变。维护会规范化 YAML 格式，不保留注释；删除来源不删除输入文件，避免误删共享/停用来源的输入。

活动指针切换是唯一提交点。导出和维护清单是提交后可恢复的投影：若磁盘错误导致同步失败，会明确报告“已提交但同步未完成”，保存 `projection-journal.json`，退出非零；先运行 `-Action recover`，成功前不要手动导入 `dist`。下一次管理操作也会先完成待恢复事务；遇到工作文件被外部改动时会拒绝覆盖。

首次成功更新会将摘要有效且通过固定核心检查的旧 `dist` 保存成一个 `legacy-dist-import` release，再激活新候选；不会覆盖或自动删除历史版本。回退只切换发布配置及版本缓存，不恢复源码、工作策略、清单或客户端选择。详见 [回退说明](docs/rollback-and-history.md)。

更新文件后，要在 SFW / SFA 各自刷新配置（profile）并确认已生效。两端保存的节点选择相互独立，更新同一份策略不会同步当前选择，也不会重置为列表首项。

## 目录

| 路径 | 内容 |
| --- | --- |
| `config\policy.yaml` | 唯一的策略文件，`config` 一节就是最终的 sing-box 配置 |
| `config\rule-sets\*.txt` | 域名名单，一行一个域名后缀 |
| `config\local\` | 本机订阅清单和订阅文件，不进 Git |
| `singbox_config\generator.py` | 生成器 |
| `singbox_config\release_manager.py` | 唯一正式事务编排与恢复实现 |
| `singbox_config\management.py` | 状态、订阅、历史、域名解释与结构检查的只读入口 |
| `singbox_config\publisher.py` | 局域网发布器 |
| `parsers\` | sing-box JSON / Clash / 节点 URI 订阅解析 |
| `dist\` | 活动版本的兼容导出；不作为发布真源 |
| `runtime\` | 完整 releases、活动指针、旧缓存、校验核心、日志和私有归档 |
| `runtime\tests\` | 每次隔离测试的独立目录；已结束测试的产物与旧源码分开保存 |
| `docs\` | 现行使用、回退与开发指南 |

## 改分流

**只想改某个域名的走向**，往名单里加一行，然后更新配置：

| 名单 | 效果 |
| --- | --- |
| `config\rule-sets\direct.txt` | 国内解析 + 直连 |
| `config\rule-sets\proxy.txt` | 代理侧解析 + 走 `Available` |
| `config\rule-sets\claude.txt` | Claude Fake-IP + 走独立 `Claude`；两项 Claude 资源精确例外走 `Aether-US` |
| `config\rule-sets\google.txt` | Google 账号生态 Fake-IP + 走 `Google`，包含 Gemini、One、登录、支付和普通 Google |
| `config\rule-sets\google-play.txt` | Android 明确的 Play 主机 Fake-IP + 走 `Google Play`，先于宽泛 Google 和视频名单 |
| `config\rule-sets\ai.txt` | 非 Google AI Fake-IP + 走 `AI`，保留共享第三方验证和遥测依赖 |
| `config\rule-sets\block.txt` | 屏蔽（DNS 返回 NXDOMAIN，连接拒绝） |

名单遵循 `policy.yaml` 的规则顺序，不是后加的名单自动覆盖前面的规则。Android 明确的 Play 匹配先于宽泛的视频和 Google 名单；YouTube 例外先于 Google 生态。多数域名由 `geosite-cn`、`geosite-geolocation-!cn` 等覆盖，未命中的域名再按解析结果判断（见下文 DNS）。国内 Android 应用与 TCP/22 不再享有特殊直连，遵循目标域名/IP；UDP/123 校时直连保留。

**其他改动**都在 `config\policy.yaml`。它的 `config` 一节按 sing-box 官方配置的结构原样书写，写什么就生成什么。生成器只额外做三件事：

1. **`only: desktop` / `only: android`**：列表里带这个标记的条目只保留在对应平台。
2. **出站**：`outbounds` 不用写，由订阅和 `groups` 生成（见下文）。
3. **规则集**：`route.rule_set` 不用写。本地同名 `.txt` 直接内嵌；上游 `geosite-xxx`、`geoip-xxx` 在构建时下载一次，用固定核心解析后内嵌。两端最终是独立的紧凑 JSON，客户端启动不下载规则。

规则原始 SRS、解析结果、来源、时间与摘要保存在 release 的 `rule-set-snapshot`，纳入完整性检查。在线更新任一必要规则下载或解析失败，本次更新失败并保留旧版；显式离线更新仅复用活动版本的完整快照，缺少新增规则时拒绝生成。首次迁移的旧 release 没有规则快照，先成功执行一次在线更新。之后需要先运行更新配置，再在客户端刷新 profile，才能取得新规则；客户端不再独立定时更新规则。

新增业务时，同时检查分组、DNS 和路由的优先级，不要只加一条路由。`test_policy_dns_rules_mirror_route_rules` 检查部分对应关系，但不能证明实际出口或 DNS/CDN 已一致；AI、视频专用 DNS、Spotify 都有有意的例外。

### 分组

| 分组 | 成员 |
| --- | --- |
| `Available` | 各订阅（多节点订阅是同名分组，单节点订阅就是节点本身），外加 `Other` |
| `AI` | 来源允许参与 AI，且地区命中 `groups.ai_regions` 或名称命中 `ai_include` 的节点；默认排除 `tls.insecure: true`，仅允许 `ai_allow_insecure` 按来源和原始完整名称声明特例；按地区排序，不自动附加 `Other` |
| `Google` | 默认跟随 AI；可选 AI、Available、Claude、两个 Meow 叶节点、四个 Aether 叶节点和 CloudLeadInno-US，共十项 |
| `Google Play` | 仅 Android；默认 Available，成员含 Available、两个 Meow 叶节点、四个 Aether 叶节点、CloudLeadInno-US 和 Claude，共九项 |
| `Claude` | 五个显式可信候选：Aether CHI/SFO/ATL 住宅 IPv6、`Aether-US-LAX-v4` 和 `CloudLeadInno-US`；无有效缓存选择时默认 CHI，手动选落地；Aether 叶节点共用原 `Aether-前置` |
| `Aether-US` | 四个 Aether 叶节点的来源选择器；无有效缓存选择且未指定 default 时使用首项 LAX-v4，不能假定客户端仍选首项 |
| `Other` | 地区识别结果为 `Others` 的节点；供 `Available`、Spotify 等分组手动选择，不作为 AI 兜底 |
| `Aether-前置` | 手动选择前置池，默认 `Aether-前置-西部数据`，故障时手动切到 `Aether-前置-备用`（羽迹） |
| `Aether-前置-西部数据` / `Aether-前置-备用` | 分别仅含西部数据港、日、台节点和已允许的羽迹节点；均为手动选择，不自动测速或换线，不含直连 |
| 其他业务分组 | 均包含 `Available` 加各订阅；`direct: first` 将直连置首（Spotify），`direct: last` 将直连放末尾（Emby）；`expand: true` 保留 `Available` 并展开订阅分组与 `Other` |

当前所有分组都是**手动选择器**。没有有效缓存选择时使用 `default` 指定的成员，未指定时使用首项；选择由各客户端的 `cache_file` 保存。手动切组会中断该组的已有连接，长下载、播放或会话可能需要重连。AI、Claude 都不包含 `Available`，不自动降级到普通出口或直连。两个前置池从 urltest 转为 selector 后，需核对首次选中节点，不能假定旧测速结果会成为新的手动选择。

`Aether-前置` 只更换到落地的中间线路，最终 Aether 落地仍由业务组手动选择。线路故障时先手动更换池内节点，或手动切到备用池。`groups.services` 的 `outbounds` 指定已有成员；`members` 可以按顺序混合分组名与 `source/names` 精确叶节点，缺失时拒绝生成；前置 `candidates` 按来源限定，完整名称与地区取并集。新增候选应验证“前置 → 落地 → 业务 HTTPS”完整链路，前置单独测速不能替代落地验收。

Google 与 Google Play 都选择 Claude 时，会共同跟随 Claude 当前落地。用户可优先使用住宅 IPv6；IPv4-only 目标仍可能失败，配置不自动切换 LAX-v4。Google Play 银行卡购买可能涉及银行等动态端点，公开 DNS 和匿名 TLS 检查不能证明整个付款流程可用。Play 商店自身有前置包名规则；Google Play 服务和框架的共享域名先按 Google 等业务规则处理，包名仅补充剩余流量。需要购买流程尽量同出口时，两组应手动选同一落地。

### AI 的使用边界

Claude 使用独立分组，`geosite-anthropic` 与本地 `claude.txt` 的规则先于普通业务和 AI 规则，但全局 STUN 与 TCP/UDP 853 拒绝仍在前。主站、API、登录和专属内容走 Claude；落地/前置失败时连接失败，不尝试后续的 AI、Available 或直连。`downloads.claude.ai` 与 `servd-anthropic-website.b-cdn.net` 两项精确资源例外走 `Aether-US`；其余 IPv4-only 依赖可手动选择兼容的可信 IPv4 落地，不自动换落地。现有已列出的 Anthropic IP 段和 Android Claude 包名也走 Claude，但不代表包含其所有 CDN 和未来地址。

当前四项资源例外分为两组，DNS 与路由各自共用 YAML 锚点：`claude-ipv4-resources` 中的 `downloads.claude.ai`、`servd-anthropic-website.b-cdn.net` 经 `aether-resources` 解析真实 IPv4、路由走 `Aether-US`；`public-ai-resources` 中的 `persistent.oaistatic.com`、`dl.google.com` 经 proxy 解析真实 IPv4、路由走 Available。均保留 UDP/443 和 IPv6 拒绝。只匹配精确主机，不扩大到子域、整个 Claude/Google 主站或整个 CDN；没有已知账号携带证据不等于保证请求始终匿名。登录、API、会话与其他 Claude 资源继续固定走 Claude。

Claude 的 `filter: trusted` 按来源和生成后的完整节点名限定叶节点，要求所有候选都存在且不关闭 TLS 校验；任一缺失、改名、来源停用或去重后消失都会阻止生成，保留上一正式版本。它禁止 `direct`、`expand`、`include` 等隐式补充和自动测速。当前已显式允许自建 LAX IPv4 与 CloudLeadInno-US。以后增加其他可信落地，先将节点放入对应订阅，再把确切名称加入 `groups.services` 的 Claude 候选；不会因为名字包含 US / v4 就自动加入。原前置与普通 AI 候选保持共用，不建立 Claude 专用前置。

普通 AI 名单保留 ChatGPT、Grok、Meta AI、Perplexity、Poe、SheerID 和共享第三方验证/遥测依赖。Google 自有生态迁入 Google，包括 Gemini、AI Studio、NotebookLM、One、登录、支付、普通搜索、邮件和共享 Google API；上游 Google 规则与本地关键域名共同覆盖地区域名。YouTube、Android Play、校时和四项精确资源保留前置例外。普通 AI 保留 `美国-德克萨斯Comcast` 的既有校验豁免，本轮不进一步收紧；严格受信名单仍仅用于 Claude。Grok / Meta AI 不整体接管 X、Facebook、Instagram 或 WhatsApp。

共享验证码/遥测主机仍走普通 AI，域名分流无法识别同一主机的请求来自 Claude 还是其他网页，不能声称所有第三方依赖都与 Claude 同出口。本地 Fake-IP 只恢复目标域名；最终 IPv6、源地址和地址租约由 VPS 控制，本项目不管理服务器的出口配置；实际地址族、出口和业务行为需要在设备端验证。

日常可在电脑和手机分别确认同一个稳定的 AI 出口，避免无故跨地区频繁切换；节点名称或“住宅”标签不保证真实出口 IP 不变。前置链路、最终节点与业务 HTTPS 的验证也不是一回事。**配置不能保证零风控**，只能减少出口跳变等可控变量；本项目不替你固定节点或修改当前选择。

## 订阅

清单是 `config\local\subscriptions.yaml`，写法和各字段说明见 [config/examples/subscriptions.yaml](config/examples/subscriptions.yaml)。最简的一条只有两行：

```yaml
subscriptions:
  - name: example
    path: subscriptions/example.url.txt   # 文件里放一行订阅链接
```

- 清单顺序就是面板顺序，第一条是 `Available` 的默认出口。
- `path` 指向的文件如果只有一行 http(s) 链接，就当作订阅地址下载；否则文件本身就是订阅内容。sing-box JSON、Clash YAML、节点 URI 列表（含整体 Base64）自动识别。
- 下载先直连，失败后经 `subscription.retry_proxy` 再试，仍失败就使用 `cache_max_age` 以内的缓存。每次两端共用一次输入；成功 release 保存本次缓存，下一进程从活动版本读取，保留原始缓存时间。`3d` 新鲜度限制不变，离线更新不延长缓存寿命。
- 缓存按 **订阅 URL + User-Agent** 隔离，避免同一 URL 的不同客户端格式相互覆盖。旧版只有 URL 的缓存无法证明 UA 身份，不自动迁移：升级后首次更新需要在线获取。在线失败不会替换活动版本，旧发布配置仍可继续使用；不会静默放宽三天有效期。
- 连接参数完全相同的节点只保留第一个；指向本机或端口无效的占位节点自动丢弃。
- 名字里带"剩余流量""套餐到期""Traffic""Expire"等字样的信息条目会保留，显示在该订阅分组的末尾；它们不是节点（`block` 出站），不进 `AI` 和 `Other`。不想看到的用 `exclude` 排除。
- 关闭了 TLS 证书校验的节点默认直接报错，确认要用再给该订阅加 `allow_insecure: true`。

## DNS

当前是**Claude、Google、已识别的 Android Play 和其他 AI 域名使用 Fake-IP，其余使用真实 IP**：

- 除四项精确资源与校时、视频等前置例外，Fake-IP 域名的 A 查询共用 `198.18.0.0/15` 池；AAAA 为空，HTTPS/SVCB 为空 NOERROR。其余查询分别跟随 Claude、Google、Google Play、AI。
- 所有代理 DNS 组提供 Google / Cloudflare 的 IPv6、IPv4 DoH 地址，始终通过同一个对应分组。地址族竞速不会改选落地，也不退回国内解析器。
- 真实地址解析分为 `domestic`（AliDNS + DNSPod，直拨）、`proxy`（经 Available）、`aether-resources`（经 Aether-US）、`youtube`、`twitch`、`emby`、`telegram`（分别跟随对应业务组）。reF1nd 的 `group` 并发使用首个无传输错误的回答，不保证回答含可用地址，也不负责更换代理节点。
- 国内与海外解析器不放在同一竞速组。名单外先用 `proxy` 的答案判断，响应命中 `geoip-cn` 时再查 `domestic`；这是改善 CDN 就近的启发式，最终路由仍取决于规则和实际目标 IP，不代表域名一定属于国内或一定直连。
- Spotify 默认直连，DNS 经 proxy 抗污染；能否直连播放需实际验证。系统 DNS 请求不一定保留应用包名，因此不声称所有商店或第三方付款请求都已识别。Telegram 的官方 IPv4/IPv6 网段均有业务路由兜底。

`optimistic.timeout: 1m` 是 **TTL 过期后**可继续使用旧答案并后台刷新的窗口，不是“切节点后一分内刷新”。YouTube/Twitch 跨地区切组后，真实 IP/CDN 仍可能受原 TTL、系统和应用缓存影响；排障时应分别检查出口与缓存，不要只反复切节点。`dns.timeout: 3s` 限制单次查询，二次解析路径可累计更久。

解析器写 IP 以免再解析其主机名。国内 DoH 省略 `detour` 即直拨，显式 detour 到当前空 `direct` 出站会被核心拒绝；不使用 `local` 是为了减少平台 DNS 依赖，不能推论所有平台的 `local` 都会回环。`reverse_mapping` 只是辅助恢复域名，不能保证识别共享 CDN、旧缓存或应用自带解析。

### IPv6 与 QUIC

两端 TUN 都接收 IPv6；全局 DNS `ipv4_only` 过滤普通 AAAA，但不等于代理远端不能使用 IPv6，也不能控制应用自带解析或硬编码地址。

YouTube、Twitch 和四项资源例外有前置 UDP/443、IPv6 拒绝；Claude、Google、AI、明确的 Android Play 匹配和商店包名有前置 UDP/443 拒绝。末尾通用拒绝只处理尚未结束匹配的流量，**不是所有 UDP/443 或 IPv6 都被阻断**：国内直连、Store、Emby、Telegram、Spotify 和共享 Play 服务的剩余包名兜底等可能已先匹配。不要把拒绝规则简单移到最前来改变已确定的业务优先策略。通用广告名单同样置于业务及国内名单之后，明确接受部分广告/遥测被放行。

## 发布

发布器固定监听 TCP `18080`，只提供配置文件：

- 本机 SFW：`http://127.0.0.1:18080/desktop/config.json`
- 其他电脑的 SFW：`http://电脑局域网IP:18080/desktop/config.json`
- Android/SFA：`http://电脑局域网IP:18080/android/config.json`；这是路径示意，远程导入必须使用带令牌的完整链接

仅回环桌面访问免认证；其他电脑和 Android 都需要令牌或 HTTP Basic Auth（凭据在 `.secrets\android-publisher.json`）。**启动默认隐藏令牌和密码**，请另开管理窗口，选择「发布与导入 → 显示导入信息」，或运行 `-Action show-info`，再复制完整带令牌链接。该操作只读取现有凭据、不创建凭据、不启动服务，也不证明服务可达。不要截图或公开粘贴完整导入信息。旧跨电脑桌面链接需要换成带令牌链接；客户端不支持时手动导入，不开放全网免认证来兼容。

每个请求只解析一次活动指针，再读取同一完整版本的配置和标记；新版本首先核对完整文件集合，配置字节核对 SHA-256。响应含 `X-Sing-Box-Build-ID` 和配置摘要。`dist` 同步失败不影响活动 release 的 HTTP 服务。发布器前台运行，`Ctrl+C` 停止；拉取与中断记在 `runtime\publisher.log`（不记录令牌查询串）。

轮换时必须先停止旧发布器；同一凭据文件的进程锁在服务整个生命周期持有，服务运行时拒绝轮换，避免出现“文件已更新、服务仍接受旧密码”。重启后旧密码失效。代码升级也需要重启旧发布器。

启动不修改端口保留、防火墙或 WinNAT。绑定失败时只诊断并退出；请手动检查 `Get-NetTCPConnection -LocalPort 18080`、`netsh interface ipv4 show excludedportrange protocol=tcp` 和本项目防火墙规则。不要重启 WinNAT 或删除其他服务的保留端口来盲目修复。

建议只允许可信 Private 网络的 LocalSubnet 访问 TCP 18080，不向公网转发。现有系统规则未自动收窄，已知旧规则为 Private/Public + Any，待用户单独确认处理。HTTP 不加密，带令牌链接和配置含节点凭据，只在可信局域网使用；不要把完整链接贴进公开日志或问题单。建议在路由器中固定电脑局域网 IP。

链接里的局域网 IP 由发布器自动探测（只认默认路由所在网卡，排除环回、链路本地和 TUN 地址段）。探测不到时会打印警告，用 `-AdvertiseHost` 指定。

### 手机拉不到配置

- **`connect: connection timed out`**：先关掉手机的移动数据。Wi-Fi 没通过 Android 联网检测时，系统会把应用的默认网络切到蜂窝，蜂窝上的连接到不了局域网。
- **关 VPN 一直等待、开 VPN 报 EOF**：手机里那条配置的远程地址是旧的 `172.18.0.1`（手机自己 TUN 的地址）。删掉该配置，重新粘贴当前打印的链接，不要只点"更新"。
- **其他 EOF / 连接被重置**：手机上正在生效的旧配置把局域网流量带进了代理。在 SFA 里断开 VPN 后再更新一次；现在的安卓配置已把私有网段排除在 TUN 之外（`route_exclude_address`），更新成功后不会复发。也可以把 `dist\android\config.json` 直接传到手机按本地配置导入。

### 连通性采样脚本

只读状态正常但网络仍不稳定时，可显式运行：

```powershell
.\scripts\quality\diagnose-connectivity.ps1 -Samples 6 -IntervalSeconds 10
```

此命令与菜单的只读诊断不同：会向固定的百度和 Google 连通性地址发起有限 HTTPS 探测，并在新建的 `runtime\connectivity-*` 目录保存采样、网卡和路由信息；不会重启客户端、切节点、清缓存或改系统网络。`system` 表示不使用显式 HTTP 代理的系统路径，**不保证经过 TUN**；`mixed` 明确使用 `127.0.0.1:7890`。失败也会记录退出码和错误并继续采样；curl 默认配置被禁用，避免用户 curlrc 额外注入请求参数。报告含本机网络信息，分享前先检查并脱敏。

## 安装与验证

```powershell
.\scripts\bootstrap\setup.bat          # 建 .venv、装依赖、生成一次配置
.\scripts\bootstrap\setup.bat -Help    # 查看前置条件与离线含义
.\scripts\bootstrap\setup.bat -Offline -NonInteractive # 仅已有环境，离线生成
.\scripts\quality\test.ps1              # 全套测试；产物只进 runtime\tests\唯一目录
python .\scripts\quality\check_public_repo.py   # 确认没有订阅、凭据进入 Git
```

安装前请准备 Python 3.10+、本机订阅清单和固定版本 CLI 核心；脚本先检查这些条件，不会自动下载核心、覆盖订阅或修改防火墙。`-Offline` 不创建虚拟环境、不执行 pip 安装、不联网下载，只校验已有 `.venv` 的锁定依赖，然后尝试复用有效缓存和完整规则快照。`-NonInteractive` 不暂停等待输入。

旧 Provider 模块与 baseline 脚本已从正式源码树移除；生成统一使用管理入口的 `-Action all`，回退使用 `-Action rollback`。

统一测试入口自动使用 `runtime\tests\run-<时间>-<随机ID>`，关闭 pytest 缓存和 Python 字节码落盘，不复用旧 basetemp、不自动删除测试历史。筛选测试可传 `-PytestArgs @('tests/test_management.py', '-q')`。更多开发与整理约定见 [开发与目录维护](docs/development.md)。Windows CI 另有固定核心集成任务：核对下载包与可执行文件 SHA-256 后执行 Windows 入口和真实核心回归，所需核心缺失时直接失败，不静默跳过。它不替代设备验收，也不会改变本机客户端版本。

`sing-box check` 不会启动完整运行链路，不能替代实际 DNS、拨号和业务验证。配置调整后，应在两端分别核对 AI 的 Fake-IP/空 AAAA、普通域名的真实地址、实际业务出口，以及视频切组和手机 Wi-Fi/蜂窝切换后的表现；测试通过也不代表全部网站、节点或网络环境均可用。

`config\local\`、`.secrets\`、`runtime\`、`dist\`、`dist-provider\`、核心二进制均不进 Git。含私密内容的实验输出和备份也应放在这些忽略目录内。

## 核心版本

配置面向 **sing-box 1.15 的 reF1nd 分支**，客户端（SFW / SFA）必须使用同一系列的核心：

- 用到的 reF1nd 专有项：DNS 的 `type: group`、`experimental.urltest_unified_delay`；后者优先采用第二次 HTTP 测速请求耗时，不是纯 RTT，也不会把手动组变为自动选路。
- DNS 的 `evaluate` / `respond`、`match_response` 来自官方 1.14 系列。当前规则集由构建程序下载并内嵌，最终配置不再使用专门下载规则的 HTTP client。
- TUN 不指定 `stack`，当前 1.15 使用 sing-tun 自身的新 TCP/IP 栈，不是沿用旧 `mixed` 默认；不指定 `udp_timeout`。桌面 MTU 使用默认值，Android 明确设为 `1400`，是移动网络的折衷而非适用所有链路的保证。

校验用的 CLI 核心放在 `runtime\cores\<版本>\`，版本由 `scripts\manage\manage.ps1` 里的 `$PreferredCoreVersion` 指定（当前 `1.15.0-alpha.11-reF1nd`，与正在使用的客户端一致，来自 [reF1nd/sing-box-releases](https://github.com/reF1nd/sing-box-releases/releases)），也可以用环境变量 `SING_BOX_CORE` 指向别处。找不到版本一致的核心时，生成和检查都会直接失败，而不是退回 PATH 上任意一个 `sing-box.exe`——SFW 安装目录里那个是 Electron 桩，执行任何命令都静默返回 0。

参考：[sing-box 配置文档](https://sing-box.sagernet.org/configuration/) · [变更日志](https://sing-box.sagernet.org/changelog/)
