# 文档导航

- [项目 README](../README.md)：菜单、命令行、配置与分流、订阅、DNS 和发布。
- [配置回退与恢复边界](rollback-and-history.md)：完整版本回退、提交后同步及旧快照导入。
- [开发与目录维护](development.md)：统一测试入口、目录边界与提交前检查。
- [订阅清单示例](../config/examples/subscriptions.yaml)：字段说明；真实输入保存在被忽略的 `config/local/`。

文档描述当前代码提供的能力。活动版本使用 `-Action status` 查询；客户端实际出口、配置刷新和节点选择需在设备端核对。

旧审计、草案、阶段交付与已退役入口已移出公开源码树，保存在本机被忽略的 `runtime/archives/` 中。它们只供追溯，不作为待执行任务。正式回退所需的 releases、backups、订阅缓存与凭据独立保留。
