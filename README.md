# sing-box 配置生成器

根据订阅生成桌面端与 Android sing-box 配置：

- 桌面端：`dist\desktop\config.json`
- Android：`dist\android\config.json`

## 版本同步约定

Windows 与 Android 的 sing-box 客户端始终保持相同版本。收到“更新 Windows 版本”的请求时，视为 Android 客户端已经由用户同步升级；维护时应同时更新两端的配置版本，不能将其拆分。

## 初始化

在 Windows 上运行：

```powershell
.\scripts\bootstrap\setup.bat
```

脚本会创建 Python 环境、下载经过校验的 sing-box 与 WinSW、保存本地订阅、生成配置并安装服务。只生成配置而不安装服务：

```powershell
.\scripts\bootstrap\setup.ps1 -SkipService
```

本地订阅和模板保存在 `config\local\`，不会被 Git 跟踪。

## 日常使用

双击 `scripts\manage\manage.bat` 打开管理菜单，可刷新配置、重启服务、生成并发布 Android 配置、打开仪表板。日常优先使用菜单的”一键刷新”：它会在临时目录生成配置，用服务将要运行的核心校验，随后原子替换正式配置；重启或健康检查失败时自动恢复上一份配置与服务定义。

也可从命令行复用同一套安全流程：

```powershell
.\scripts\manage\manage.ps1 -Action reload
.\scripts\manage\manage.ps1 -Action offline-reload
.\scripts\manage\manage.ps1 -Action publish
.\scripts\manage\manage.ps1 -Action offline-publish
.\scripts\manage\manage.ps1 -Action status
```

`publish` 在临时目录生成并校验 Android 配置，通过后原子替换 `dist\android\config.json`，再在固定端口 `8888` 启动局域网发布器。固定端口使手机可长期保存同一远程地址；发布器已运行时直接复用。执行 `stop-publish` 或在菜单选择 `[x]` 可停止发布。`status` 核对服务状态、实际核心版本、`sing-box check`、控制接口及 `Available`、`DNS-Out`、`AI`、`Emby` 当前选择。菜单的日志项跟随核心实际写入的 `singbox-service.err.log`。

也可直接生成：

```powershell
python .\scripts\config\generate_config.py all
python .\scripts\config\generate_config.py desktop
python .\scripts\config\generate_config.py android
```

只使用已有订阅缓存：

```powershell
python .\scripts\config\generate_config.py all --offline
```

订阅下载需要代理时：

```powershell
python .\scripts\config\generate_config.py all --fetch-proxy http://127.0.0.1:7890
```

## Android 远程配置

在 `manage.bat` 菜单选择 `[a]` 或执行 `manage.ps1 -Action publish`，会生成并发布 Android 配置到固定端口 `8888`。手机与电脑需在同一可信局域网。脚本显示的远程配置地址包含真实节点凭据，不要暴露到公网。首次在 SFA 添加远程配置后，日常只需在电脑运行菜单 `[a]`，再在手机点更新，无需修改 URL。

## 分流与分组

- 国内域名和 IP 直连，其余流量默认走 `Available`；`Available` 本身为手动选择。
- 每个机场保留独立分组；自建节点直接列入 `Available` 和 `Emby`。
- 订阅开启 `urltest: true` 时，仅该机场生成 `{机场}/Auto`（无全局 Auto）。
- `AI` 仅使用美国节点，订阅可通过 `ai_exclude: true` 整体排除（本地配置用它排除良心云）；`Emby` 默认同 `Available`，可选手动或 `direct`。
- `DNS-Out` 默认优先选择安全的自建节点，也可手动切换为 `Available` 或 `direct`；它只承载干净 DNS 和桌面规则更新，不跟随日常 `Available` 切换，避免一次故障同时打断数据面与控制面。
- DNS：境外查询经独立的手动 `DNS-Out` 组访问干净 DoH；节点域名解析用直连 `bootstrap` DNS；桌面端规则集经 `DNS-Out` 下载，安卓端经 `Available` 下载，避免 CDN 的直连 DNS 故障影响规则更新。
- Android 的 Google Play 与桌面端 Microsoft Store 使用代理和干净 DNS，位置在 Clash 模式开关之下、国内规则之上。
- 内置一份国内主要域名清单（腾讯/微信、阿里、字节、B 站、手机厂商等）直连并走 `local` DNS，与 `geosite-cn` 结果一致，只是不依赖下载；规则集缺失时国内分流仍然成立。
- 广告拦截只拒绝境外广告网络：`geosite-category-ads-all` 与 `geosite-cn`（及上述国内清单）取交集后排除，因为该规则集把 `badjs.weixinbridge.com`、`tcss.qq.com`、`log.tbs.qq.com`、`beacon.qq.com` 等国内 App 的必需上报域名也算作广告，一律拒绝会导致微信公众号页面加载不出来。
- Direct/Proxy 模式覆盖业务分流；AI、Emby、Telegram 等专用规则显式限定在 Rule 模式。
- 桌面端远程规则集使用 `runtime\rule-set-cache` 作为 1.14 `initial_path`，首次启动仍会在后台更新。

订阅默认保留全部节点；设置 `hot_regions_only: true` 后只保留香港、美国、台湾、日本、新加坡、法国和英国。生成前会确认香港、美国、台湾、日本、新加坡均有可用节点。

订阅清单示例：

```yaml
subscriptions:
  - name: provider
    parser: clash
    source: url_file
    path: subscriptions/provider.txt

  - name: self-hosted
    self_hosted: true
    parser: uri
    source: file
    path: subscriptions/self-hosted.txt
```

支持 `clash`、`singbox-json` 和常见 URI 协议。

## 目录

- `config/examples/`：可公开的脱敏示例
- `config/local/`：本机订阅、模板和策略
- `config/services/`：Windows 服务模板
- `scripts/`：初始化、管理、发布和检查入口
- `singbox_config/`、`parsers/`：生成器与解析器
- `web/traffic-dashboard/`：本地流量统计界面
- `runtime/`：核心、服务副本、sing-box 状态缓存、规则/订阅缓存、数据库和日志

- 实时连接仪表板：`http://127.0.0.1:9090/ui/`
- 流量统计面板：`http://127.0.0.1:9091`

## 验证

```powershell
python -m pytest
python .\scripts\quality\check_public_repo.py
```

`config\local\`、`runtime\`、`dist\`、数据库、日志、二进制和订阅凭据均不得提交。
