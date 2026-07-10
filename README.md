# sing-box 配置生成器

这个项目只做一件事：根据你的订阅生成两份可导入的 sing-box 配置。

- 桌面端：`dist\desktop\config.json`
- 安卓端：`dist\android\config.json`

不会再把日常使用拆成多个 profile，也不会自动部署 Windows 服务、回滚服务或打包 Android 发布物。

## 日常使用

双击 `reload.bat`，它会生成桌面端和安卓端配置。

也可以只生成一个目标：

```bat
reload.bat desktop
reload.bat android
```

命令行等价写法：

```powershell
python .\generate_config.py all
python .\generate_config.py desktop
python .\generate_config.py android
```

生成完成后，把对应的 `config.json` 导入桌面或 Android 的 sing-box 客户端即可。

桌面配置默认开启本机仪表板。启动桌面端配置或 Windows 服务后，可访问 `http://127.0.0.1:9090`。

## 首次设置

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

配置会建立七个顶层地区分组：`地区/香港`、`地区/美国`、`地区/台湾`、`地区/日本`、`地区/新加坡`、`地区/法国`、`地区/英国`，可用于其他应用分流。每个机场保留为独立订阅分组，所有自建节点只出现在一个 `自建` 分组。`Available` 只列出机场订阅分组和 `自建`；`AI` 只列出美国节点。

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
```
