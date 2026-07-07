# sing-box 本地配置说明

这个目录用于从多个自建节点、mikasa 机场和良心云订阅生成 `config.json`，并通过 `singbox-service.exe` 作为 Windows 服务运行 sing-box。

当前 sing-box 版本：`1.14.0-alpha.39`。

## 日常使用

双击或运行：

```bat
reload.bat
```

脚本会按顺序执行：

1. 根据 `subscriptions.yaml` 和 `template.json` 生成 `config.next.json`
2. 使用 `sing-box.exe check -c config.next.json` 校验配置
3. 校验通过后备份旧 `config.json` 到 `backups/`，再替换 `config.json` 并重启 sing-box 服务

如果订阅临时下载失败，生成脚本会优先使用 `.subscription-cache` 里的缓存，避免服务被坏配置覆盖。

控制面板地址：

```text
http://127.0.0.1:9090/ui/
```

本地同时提供 `mixed-in` 入口：

```text
127.0.0.1:7890
```

## 分组含义

`Available` 是日常默认出口，只保留手选组：`瓦工自建`、`白丝云自建`、`RN自建`、`Provider/mikasa机场`、`良心云` 和 `direct`。

`AI` 是 OpenAI、Claude、Gemini 等 AI 站点的默认出口。默认走 `瓦工自建`，并保留所有美国节点作为手动应急出口。

`Provider` 是按订阅来源查看节点的入口。当前包含 `瓦工自建`、`白丝云自建`、`RN自建`、`Provider/mikasa机场`、`良心云` 和 `direct`。

`白丝云自建` 是原 `自建结点` 分组改名后的自建节点，当前作为 `urltest` 出站周期测速。

`RN自建` 是 Clash 格式订阅导入的自建节点，当前作为扁平手选组。

`Provider/mikasa机场` 是扁平手选组，只保留香港、台湾、日本、新加坡、美国和英国节点，不再按地区拆分，也不再生成 `Auto` 自动测速组。

`良心云` 是扁平手选组，只保留香港、台湾、日本、新加坡、美国和英国节点。

`direct` 表示直连，`block` 表示阻断。

当前生成器默认不生成 `urltest` 自动测速分组；只有在订阅项显式设置 `urltest: true` 时才会生成测速出站。

## 核心分流

本地、私有地址、CN geosite/geoip 默认直连。

DNS 规则使用官方当前的 `action: route` 写法，国内域名走本地 DNS，默认和代理相关域名走 DoH。本地 DNS 主用 `223.5.5.5`，备用 `119.29.29.29`；两者都从 TUN 路由中排除并显式直连，减少网卡切换时本地 DNS 被代理链路牵连的概率。`independent_cache` 在 1.14.0 已废弃，DNS 缓存隔离交给 sing-box 当前实现处理。

AI 站点走 `AI` 分组，默认使用 `瓦工自建`；如果瓦工故障，可以在 `AI` 分组手动切到任一美国节点。`sub.ddpapi.top` 和 `hayi.cc.cd` 固定走 `瓦工自建`。

流媒体和常见国外服务当前显式包含 YouTube/Google 视频、Telegram、Google 通用服务、Spotify、部分 Microsoft/Visual Studio/Skype 域名，走 `Available`。这些规则排在 `clash_mode: Direct` 之前，用于降低面板误切 Direct 时海外服务被直连的概率。

BT 协议直连，避免误走付费机场。

`csdiy.wiki`、`oi-wiki.org` 和指定 GitHub Pages 地址直连，并启用 `tls_record_fragment` 处理直连 TLS 握手中断。

`verykuai.com`、`paperyy.com`、`sharedchat.cc`、`ai.hybgzs.com`、`cdk.hybgzs.com` 直连。

`linux.do` 走 `Available`，DNS 使用远程 DoH。

GitHub Release 下载相关域名（`github.com`、`release-assets.githubusercontent.com`、`objects.githubusercontent.com` 等）走 `Provider/mikasa机场`，DNS 使用远程 DoH。此规则排在 GitHub IP 直连规则之前，避免 Release 资产解析到 `185.199.108.0/22` 后被误判为直连。

Windows 连通性探测域名 `msftconnecttest.com` 和 `msftncsi.com` 直连并使用本地 DNS，避免系统网络状态检测被代理节点或远程 DNS 抖动影响。Direct 模式下 DNS 使用备用本地 DNS，避免和 Rule 模式的主本地 DNS 缓存完全耦合。

TUN 入口默认关闭 `endpoint_independent_nat`，减少不必要的 NAT 开销；只有特定 UDP/P2P 应用明确需要时再临时开启。TUN MTU 使用 `1500`，并排除私有网段、CGNAT、链路本地和组播地址，优先保证 Windows 和局域网兼容性。

远程 `geosite-cn`/`geoip-cn` 规则集按 `1d` 更新，下载使用显式 `http_clients`/`route.default_http_client`，并通过 `rule-set-downloader` 走 `Available`。1.14.0 起不再使用废弃的 `download_detour` 字段。

## 1.14 配置依据

本目录的 1.14 配置调整只参考 sing-box 官方材料：

- `https://github.com/SagerNet/sing-box/releases/tag/v1.14.0-alpha.39`
- `https://sing-box.sagernet.org/deprecated/`
- `https://sing-box.sagernet.org/configuration/`
- `https://sing-box.sagernet.org/configuration/route/`
- `https://sing-box.sagernet.org/configuration/shared/http-client/`
- `https://sing-box.sagernet.org/configuration/shared/dial/`

关键改动：

- 新增顶层 `http_clients`，并设置 `route.default_http_client`。
- 远程规则集从 `download_detour` 改为 `http_client`。
- 移除 `dns.independent_cache`。

## 订阅配置

订阅清单包含自建节点、mikasa 和良心云：

```yaml
subscriptions:
  - name: mikasa机场
    enabled: true
    priority: 20
    role: backup
    parser: clash
    source: url_file
    path: subscriptions/Provider-mikasa机场.txt
    hot_regions_only: true
    flat_group: true
    include_in_available: true
    available_priority: 40
  - name: 良心云
    enabled: true
    priority: 21
    role: backup
    parser: clash
    source: url_file
    path: subscriptions/良心云.txt
    group_tag: 良心云
    hot_regions_only: true
    flat_group: true
    include_in_available: true
    available_priority: 50
  - name: 瓦工自建
    enabled: true
    priority: 10
    role: primary
    parser: uri
    source: file
    path: subscriptions/瓦工自建.txt
    group_tag: 瓦工自建
    flat_group: true
    include_in_available: true
    available_priority: 20
  - name: 白丝云自建
    enabled: true
    priority: 11
    role: primary
    parser: uri
    source: file
    path: subscriptions/白丝云自建.txt
    group_tag: 白丝云自建
    flat_group: true
    urltest: true
    urltest_url: https://cp.cloudflare.com/generate_204
    include_in_available: true
    available_priority: 30
  - name: RN自建
    enabled: true
    priority: 12
    role: primary
    parser: clash
    source: url_file
    path: subscriptions/RN自建.txt
    group_tag: RN自建
    flat_group: true
    include_in_available: true
    available_priority: 35
```

订阅源文件统一放在 `subscriptions/` 目录，文件名和代理组名保持一致；`Provider/mikasa机场` 因为包含路径分隔符，文件名写作 `Provider-mikasa机场.txt`。不要分享 `subscriptions/`、`.subscription-cache` 或生成后的 `config.json`，里面可能包含订阅地址或节点凭据。

## 手动命令

只生成配置：

```powershell
python .\build_singbox.py --template .\template.json --output .\config.json
```

校验配置：

```powershell
.\sing-box.exe check -c .\config.json
```

重启服务：

```powershell
.\singbox-service.exe restart
```

查看服务状态：

```powershell
.\singbox-service.exe status
```

## Git 备份

本目录是本地 git 仓库，用来备份模板、生成器、解析器、订阅清单和生成后的配置文件。

不会纳入版本库的内容包括：`subscriptions/`、`.subscription-cache/`、`logs/`、`backups/`、下载包、二进制文件、缓存数据库和 dashboard 静态资源。`config.json` 可能包含节点凭据，只建议保留在本地私有仓库，不要推送到公开远程。

## 日志

配置默认使用 `warn` 日志级别，运行日志交给 `singbox-service.exe` 的滚动日志处理。

需要排错时，可以临时把 `template.json` 里的 `log.level` 改成 `info`，重新运行 `reload.bat`。排错结束后建议改回 `warn`。
