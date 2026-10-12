# 发布检查清单

发布的是 GS 6.0（`v6.*` tag 触发 CI 出多平台包）。5.2 已退役，不再有
“替换全局 5.2”这一步，也不再需要 5.2 回滚路径。

## 1. 代码就绪

- [ ] `cd rust && cargo test --workspace` 全绿
- [ ] `cargo fmt --all -- --check` 干净
- [ ] `cargo clippy --workspace --all-targets` 无告警
- [ ] `python3 scripts/audit_plugins.py` 无问题
- [ ] `bash scripts/stage_release.sh && bash scripts/verify_gs.sh` 通过
- [ ] 没有未提交改动；`gs6`/`-6` 之类的旧命名没有回流

## 2. 版本一致

- [ ] `python3 scripts/prepare_release.py --version <版本>` 检查通过
  （前端版本、core 版本、各 `plugin.toml`、安装脚本内的默认版本一致）
- [ ] `plugins/*/plugin.toml` 全部为本次版本；数量为当前公开插件数（13）
- [ ] `docs/changelog.md` 已加本次条目

## 3. 打包与验证

- [ ] 打 tag（`v6.x.y`）触发 `.github/workflows/release.yml`
- [ ] 每个平台产物都跑过 `scripts/verify_package.py --root <目录> --target <target>`
      （校验 SHA256SUMS、插件数、`bad plugin list` 摘要、doctor、shell-init 等）
- [ ] 包内**不含**私有插件与私钥/token/公司配置
- [ ] `scripts/verify_shells.sh` 在 bash/zsh/fish 下通过（Windows 走
      `verify_powershell.ps1`）

## 4. 安装冒烟（在干净环境）

```bash
bash scripts/install_gs.sh --yes
gs version && gs doctor && gs plugin list
gs completions fish --install && gs shell-init fish > /tmp/gs.fish
bash scripts/uninstall_gs.sh --yes     # 只删 gs，其它入口不动
```

## 5. 发布说明

- [ ] 说明本次新增/变更的命令，以及任何破坏性改动（重命名不保留别名）
- [ ] 若涉及协议变化，更新 [docs/protocol.md](./protocol.md) 与 `protocol` 版本

## 相关文档

- [跨平台发布](./cross-platform-release.md) · [安装指南](./installation.md) · [迁移状态](./migration-status.md)
