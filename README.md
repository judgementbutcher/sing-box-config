# sing-box 配置生成器

根据订阅生成桌面端与 Android sing-box 配置：

- 桌面端：`dist\desktop\config.json`
- Android：`dist\android\config.json`

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

双击 `scripts\manage\manage.bat` 打开管理菜单，可刷新配置、重启服务、生成 Android 配置并打开仪表板。

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

先生成 Android 配置，再运行：

```powershell
.\scripts\serve\serve_android.bat
```

手机与电脑需在同一可信局域网。脚本会显示 SFA 远程配置地址；该地址提供的文件包含真实节点凭据，不要暴露到公网。

## 分流与分组

- 国内域名和 IP 直连，其余流量默认走 `Available`；`Available` 本身为手动选择。
- 每个机场保留独立分组；自建节点直接列入 `Available` 和 `Emby`。
- 订阅开启 `urltest: true` 时，仅该机场生成 `{机场}/Auto`（无全局 Auto）。
- `AI` 使用美国节点及 `ai_include` 自建节点，保持手动选择；`Emby` 默认同 `Available`，可选手动或 `direct`。
- DNS：境外查询经 `Available` 的干净 DoH；节点域名解析用直连 `bootstrap` DoH；规则集下载直连。
- Android 的 Google Play 与桌面端 Microsoft Store 使用代理和干净 DNS。

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
- `runtime/`：核心、服务副本、缓存、数据库和日志

- 实时连接仪表板：`http://127.0.0.1:9090`
- 流量统计面板：`http://127.0.0.1:9091`

## 验证

```powershell
python -m pytest
python .\scripts\quality\check_public_repo.py
```

`config\local\`、`runtime\`、`dist\`、数据库、日志、二进制和订阅凭据均不得提交。
