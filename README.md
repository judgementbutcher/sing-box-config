# sing-box 配置生成器

这个项目根据你的订阅生成桌面端和安卓端 sing-box 配置。

- 桌面端：`dist\desktop\config.json`
- 安卓端：`dist\android\config.json`

不会再把日常使用拆成多个 profile，也不会在日常刷新时重复部署 Windows 服务、管理回滚服务或打包 Android 发布物；Windows 服务只由首次初始化脚本安装。

## 新电脑恢复

公开仓库不包含订阅，但包含从空白 Windows 环境恢复所需的其余内容。新电脑只需：

```powershell
git clone https://github.com/judgementbutcher/sing-box-config.git
cd sing-box-config
.\setup.bat
```

按提示粘贴订阅链接即可。脚本会在本机保存订阅、创建 Python 虚拟环境、安装依赖、下载并校验固定版本的 sing-box 与 Windows 服务包装器、生成配置，然后请求管理员权限安装并启动服务。订阅链接不会作为命令行参数传递，也不会被 Git 跟踪。

如果只需要生成桌面和 Android 配置，不安装 Windows 服务：

```powershell
.\setup.ps1 -SkipService
```

默认按 Clash YAML 解析订阅；sing-box JSON 或 URI 列表可分别使用 `-Parser singbox-json` 或 `-Parser uri`。订阅下载需要经过已有代理时可加 `-FetchProxy http://127.0.0.1:7890`。

## 日常使用

双击 `manage.bat` 进入统一管理菜单。日常刷新选择 `[1]`，它会生成桌面端配置，然后重启 sing-box Windows 服务。

根目录只保留 `setup.bat`（首次初始化）和 `manage.bat`（日常管理）两个入口。兼容旧用法的次级脚本统一放在 `tools\`：

```bat
tools\reload.bat
tools\build_android.bat
```

两个脚本都可以接收生成器选项，例如 `tools\reload.bat --offline` 或 `tools\build_android.bat --offline`。

命令行等价写法：

```powershell
python .\generate_config.py all
python .\generate_config.py desktop
python .\generate_config.py android
```

桌面服务读取 `dist\desktop\config.json`。

### 安卓端：局域网远程订阅（免手动复制）

不用再每次把文件拷进手机。sing-box for Android（SFA）支持「远程配置」，桌面在局域网发布一次，手机以后点一下就能更新：

1. 桌面发布配置（二选一）：
   - 双击 `tools\serve_android.bat`（会先检查 `dist\android\config.json` 是否已生成）；或
   - 运行 `manage.bat` 选 `[a] 安卓配置：生成并局域网发布`（先重新生成再发布）。

   发布窗口会打印手机要用的地址，形如 `http://192.168.x.x:8080/android/config.json`。
2. 手机 SFA：新建配置 → 类型选「远程」→ 名称随意 → 地址粘贴上面的 URL → 保存；可在该配置里打开自动更新。
3. 以后刷新：桌面重新生成安卓配置（`tools\build_android.bat` 或菜单 `[a]`），手机在 SFA 点该配置的「更新」即可，无需再复制文件。

注意事项：

- 手机和电脑要在同一局域网；首次可能弹出 Windows 防火墙提示，勾选「专用网络」允许即可。
- 发布的文件含真实节点凭据，只在可信网络使用，不要把该端口转发到公网。
- 端口被占用时可换端口：`tools\serve_android.bat --port 8888`。
- 仍可退回手动方式：直接把 `dist\android\config.json` 导入 SFA。

桌面配置默认开启本机实时连接仪表板。启动桌面端配置或 Windows 服务后，可访问 `http://127.0.0.1:9090`。

### 流量去向统计

普通运行日志只适合排错，不包含每条连接最终使用的完整字节数，因此不能用现有日志准确回答“流量主要去了哪里”。项目额外提供本地统计器：持续读取 sing-box 的 Clash API 活动连接计数，把字节增量保存在 `runtime\traffic-monitor.db`，并按以下维度汇总：

- 站点与完整域名 / IP，并可按今天、昨天、近 7 天、近 30 天或全部时间查看；
- Windows 应用进程；
- 命中的分流规则；
- 实际出口节点与完整出口链，并可筛选全部、仅代理或仅直连流量。

首次安装后统计器会作为 `sing-box-traffic` Windows 服务自动启动，面板地址为 `http://127.0.0.1:9091`。日常也可双击 `manage.bat`，选择 `[t] 打开流量去向统计`；若尚未安装服务，管理脚本会以当前用户临时启动统计器。

统计器只监听 `127.0.0.1`，只保存连接元数据和上传/下载字节数，不保存网页内容、请求正文或 TLS 明文。连接若恰好在两次一秒采样之间建立并关闭，总字节数仍会根据 sing-box 全局计数补入，但会单列为“未识别”，不会伪造域名归属。刚启用时，当前 sing-box 进程启动以来已经结束的连接同样只能计入“未识别”；持续运行后可归属比例会逐渐提高。

也可手工运行：

```powershell
.\.venv\Scripts\python.exe .\traffic_monitor.py
```

## 首次设置

推荐直接运行 `setup.bat`。以下是需要管理多个订阅或本地自建节点时的手工方式。

1. 准备订阅清单：

   ```powershell
   Copy-Item .\subscriptions.example.yaml .\subscriptions.yaml
   ```

2. 在 `subscriptions.yaml` 中填写每个订阅的名称、格式和位置。URL 文件中只放一行订阅地址；本地节点文件可使用 `source: file`。

3. 准备模板。项目会优先使用：

   - `templates\desktop-windows-sing-box-1.14.json`
   - `templates\mobile-android-sing-box-1.13.14.json`

   如果其中之一不存在，会退回使用 `template.json`，最后才使用脱敏的 `template.example.json`。

4. 安装依赖：

   ```powershell
   python -m pip install -r .\requirements.lock
   ```

若要只从已有缓存生成配置：

```powershell
python .\generate_config.py all --offline
```

订阅下载需要经过本地代理时可传入：

```powershell
python .\generate_config.py all --fetch-proxy http://127.0.0.1:7890
```

## 节点保留规则

机场订阅只保留香港、美国、台湾、日本、新加坡、法国、英国节点；其他地区机场节点不会写入最终配置。所有标记为自建的订阅会完整保留，并合并到一个 `自建` 组。旧的 `hot_regions_only`、每地区限额、总节点限额或 Android 限额不会影响这七个地区的保留数量。完全相同的节点会合并一次，避免在配置中重复；只有你在订阅清单里明确写出的 `include_nodes` / `exclude_nodes` 才会继续生效。

每次生成都会检查以下地区是否至少有一个节点：香港、美国、台湾、日本、新加坡、法国、英国。任一地区缺失时，生成会失败且不会覆盖已有的桌面或 Android 配置；这样不会悄悄产出缺地区的配置。节点名称中的 `法国`、`France`、`Paris`、`FR` 或法国国旗都会识别为法国节点。

配置的分组：每个机场保留为独立订阅分组，所有自建节点合并到一个 `自建` 分组。`Available` 只列出机场订阅分组和 `自建`，是全局默认出口；`AI` 只列出美国节点（及标记 `ai_include` 的自建）。此外为常用大服务单独建了分流分组：`谷歌`、`YouTube`、`Netflix`、`Telegram`、`社交媒体`、`微软`、`苹果`、`游戏平台`。每个服务分组的成员与 `Available` 一致，且把 `Available` 排在第一位——默认跟随全局选择，需要时可把某个服务单独钉到指定机场做精细分流。对应服务的域名会直接路由到各自的分组，其余海外流量仍走 `Available`。

## 订阅清单示例

```yaml
subscriptions:
  - name: my-provider
    parser: clash
    source: url_file
    path: subscriptions/my-provider.txt

  - name: self-hosted
    self_hosted: true
    parser: uri
    source: file
    path: subscriptions/self-hosted.txt
```

支持 `clash`、`singbox-json` 和常见 URI 协议。旧清单中的 `priority`、`role`、`group_tag` 等字段仍可读取，但日常生成不再依赖它们做节点裁剪。

## 验证

```powershell
python -m pytest
python .\check_public_repo.py
```

## 可推送边界

可以推送：Python 生成器与解析器、测试、脱敏的 `*.example.*`、启动/初始化脚本、服务 XML、依赖锁定文件和 CI。初始化脚本只保存版本号、公开下载地址和文件校验值，不包含任何订阅信息。

不能推送：`subscriptions.yaml`、`subscriptions\`、订阅缓存、`template.json` 与私有模板、生成配置、节点报告、数据库、日志、二进制、虚拟环境、`.secrets\` 和本地说明。这些路径均由 `.gitignore` 排除，CI 还会运行 `check_public_repo.py` 阻止误提交。

推送前运行：

```powershell
python .\check_public_repo.py
git status --short
```

注意：`.gitignore` 和检查脚本只能保护新提交。如果 Git 历史中曾提交过真实订阅链接或节点凭据，应先在服务商处轮换订阅链接，再重写远端历史；仅删除当前文件不足以清除旧提交。
