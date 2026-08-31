# GS 6.0 发布前检查清单

GS6 正式替换全局 5.2 前必须完成以下事项：

1. `scripts/verify_gs6.sh` 通过。
2. Rust workspace、Python 非慢速测试和 SDK self-test 通过。
3. Android 设备在线时运行 `scripts/verify_android_device.sh`。
4. 确认所有正式插件版本为 `6.0.0-dev`，并决定正式版本号。
   正式冻结时运行：`python3 scripts/prepare_gs6_release.py --from-version 6.0.0-dev --version 6.0.0 --write`，随后执行 Cargo 检查刷新 lockfile。
5. 明确哪些当前真实操作继续开放，哪些需要恢复 dry-run 或增加确认。GS6 对有副作用的命令统一要求显式 `--yes`；`--dry-run` 仍是默认验收路径。
6. 在独立 shell 会话验证 Bash/Zsh/Fish/PowerShell 补全和 `shell-init`。
7. 备份并记录当前 5.2 全局入口、配置、缓存和 shell 函数。
8. 先以独立入口灰度运行 GS6，再考虑替换全局 `gs`。
9. 保留 5.2 回滚路径，并验证回滚后旧入口可用。
10. 执行 `scripts/stage_gs6_release.sh`，确认 `dist/gs6-dev` 可独立运行后再分发。
11. 使用 `scripts/rollback_gs52.sh` 验证 5.2 二进制可从 `LATEST_GS52` 备份恢复。
12. 执行 `scripts/audit_gs6_ready.sh`，确认 staging、备份、回滚和全局入口状态一致。
13. 使用 `scripts/install_gs6.sh --yes` 只安装独立的 `gs6` 灰度入口；该脚本不得覆盖全局 `gs`。
14. Frida 的 `frida-server`/`frida-inject` 是可选的大型发布资产，不作为普通 Git 源文件管理；使用 `scripts/fetch_frida_android_arm64.sh` 从官方 Release 获取。staging 在本地资产存在时会打包并纳入 `SHA256SUMS`。
15. 执行 `uv run python scripts/audit_gs6_command_parity.py`，确认缺失命令归零或已有明确的删除 ADR。
16. 通过 `.github/workflows/gs6-release.yml` 生成并验证 macOS、Linux、Windows 对应架构的便携包。
17. 执行 `bash scripts/verify_gs6_shells.sh`，确认 Bash、Zsh、Fish 的补全、环境变量回传和目录切换均通过。
18. 使用隔离的 `GS6_PREFIX`/`HOME` 验证 `install_gs6.sh` 与 `uninstall_gs6.sh` 往返后不残留文件，也不修改全局 `gs`。
19. 正式 tag 前配置 Apple Developer ID/notarization 和 Windows Authenticode secrets；tag workflow 必须完成签名验证和 macOS notarization。

当前状态：核心框架、15 个正式插件、命令兼容性审计、Android 实机验证、独立安装/回滚演练和 release staging 已完成；多平台发布工作流仍需在 GitHub Actions 原生 runner 上实际跑通，因此暂不切换全局入口。
