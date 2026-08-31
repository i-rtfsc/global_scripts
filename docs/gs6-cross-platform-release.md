# GS6 跨平台构建与发布

Rust 二进制必须针对操作系统和 CPU 架构分别编译，不能将 macOS ARM64 二进制直接用于
Intel Mac、Linux 或 Windows。

`.github/workflows/gs6-release.yml` 当前生成以下便携 ZIP：

- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`

每个 ZIP 包含原生 `gs6` 二进制、正式插件、Python SDK、主题、Shell 补全、
Bash/Zsh/Fish/PowerShell Shell init 和 `SHA256SUMS`。原生二进制会从自身所在目录发现 `plugins/`
与 `sdk/`，便携包不依赖 Bash wrapper。

本地打包示例：

```bash
cargo build --release --manifest-path rust/Cargo.toml
python3 scripts/package_gs6.py \
  --binary rust/target/release/gs \
  --output dist/gs6-aarch64-apple-darwin \
  --archive dist/gs6-aarch64-apple-darwin.zip \
  --target aarch64-apple-darwin
```

Windows runner 会验证 PowerShell 补全、当前会话环境变量回传和 `navigator` 目录切换。
Unix 专属外部工具（例如 Homebrew、SSHFS 或 AOSP Bash 构建脚本）仍需在命令层面检查依赖；
跨平台构建成功不表示这些外部工具会自动存在。

## 未签名发布

GS6 是免费开源命令行工具，发布包不提供商业代码签名或 Apple notarization。所有平台产物
均标记为 `signed: false`，由用户自行下载、校验和安装。

- 下载后应核对 ZIP 内的 `SHA256SUMS`。
- macOS Gatekeeper 可能提示来源未验证；用户需自行确认来源后允许执行。
- Windows SmartScreen 可能显示未知发布者；用户需自行确认来源后运行。

Release workflow 不需要证书 secrets，也不会把未签名包描述成已签名软件。
