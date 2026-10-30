# 开发与目录维护

本页描述现行仓库维护方式，不是生产配置更新步骤。日常使用见[项目 README](../README.md)，版本恢复见[回退说明](rollback-and-history.md)。

## 目录边界

| 目录 | 用途 | 是否进入 Git |
| --- | --- | --- |
| `singbox_config/`、`parsers/` | 正式 Python 实现 | 是 |
| `config/policy.yaml`、`config/rule-sets/`、`config/examples/` | 策略、名单与脱敏示例 | 是 |
| `scripts/bootstrap/`、`scripts/manage/`、`scripts/quality/` | 安装、管理与质量检查入口 | 是 |
| `tests/` | 合成输入的单元与隔离集成测试 | 是 |
| `docs/` | 现行使用、回退与开发指南 | 是 |
| `config/local/`、`.secrets/`、`.claude/settings.local.json` | 本机订阅、凭据与工具设置 | 否 |
| `runtime/`、`dist/`、`.venv/`、运行数据库 | 发布状态、导出、环境与本机数据 | 否 |

旧 Provider 模块、baseline 脚本及其占位入口已从正式源码树移除。生成与回退统一使用管理入口；不要重新引入可直接覆盖 dist 的旁路。未跟踪的源码、规则或测试需要先核对用途，再决定提交或清理。

## 统一测试入口

在仓库根目录的 PowerShell 中运行：

```powershell
.\scripts\quality\test.ps1
.\scripts\quality\test.ps1 -PytestArgs @('tests/test_management.py', '-q')
.\scripts\quality\test.ps1 -PytestArgs @('-k', 'not real_core', '-q')
```

入口优先使用项目 `.venv`，否则使用 PATH 中的 Python；不安装依赖、不下载核心。每次使用全新的 `runtime/tests/run-<时间>-<随机ID>`，关闭 pytest 缓存与 Python 字节码落盘，保留 pytest 退出码。为避免 pytest 清空错误目录，不允许覆盖 basetemp、缓存或插件控制参数；外部 pytest 附加参数在本次调用中被隔离，结束后恢复环境。

测试脚本不是安全沙箱：测试代码本身仍会执行；部分集成测试会启动仅监听本机回环地址的临时服务和合成配置核心，不启用 TUN、不连接真实代理节点。缺少可选核心时，本地相关用例可能跳过；CI 的固定核心集成任务要求核心存在，否则直接失败。网络限制导致的失败应单独诊断，不能记作通过。

手动运行 pytest 时，不要将已有工作目录传给 `--basetemp`，pytest 会清空该目录。推荐始终使用统一入口，避免依赖系统 Temp 权限或将大量测试目录散落到 `runtime` 顶层。

## 整理与历史保留

- 本次整理涉及的旧测试产物已永久删除，不再另存归档。新测试使用 `runtime/tests/run-*`，产物保留到核验结束后再按需清理。
- 活动指针、完整 releases、backups、核心、订阅缓存、发布凭据和客户端数据库不是测试垃圾，不随目录整理移动或删除。
- 经确认不再使用的过时文档和退役入口直接删除，不额外归档；已提交源码可通过 Git 历史追溯。原有私有审计证据保留原路径。
- 已结束测试的目录可在核对路径和进程状态后清理；测试运行时不清理产物。正式日志、回退版本和审计证据不与测试产物混删。

## 提交前检查

```powershell
.\scripts\quality\test.ps1
.\.venv\Scripts\python.exe .\scripts\quality\check_public_repo.py
git diff --check
git status --short
```

公开检查同时查看候选工作区文件和暂存内容，阻止已知私密路径、节点 URI 与令牌查询串；它不是通用秘密检测器，不能证明任意 JSON 字段或路径式令牌已经脱敏。暂存时只选择审核过的源码、策略、测试和文档，不强制添加忽略目录；提交后再次检查扫描结果与 Git 状态。整理源码、创建 Git 提交和激活配置是三件不同的事，提交不会替客户端刷新配置。
