# GS 6.0 迁移状态

## 当前状态

GS 6.0 是唯一运行时。仓库里每个插件只有一个 `plugin.toml` 与一份实现。

| 项 | 值 |
|---|---|
| 公开插件 | 13（见 `gs plugin list`） |
| 私有插件 | `sgm` / `flyme`，只在 `custom/userspace/`（不入库、不进包） |
| 前门 | Rust（`rust/crates/gs`）+ 核心（`rust/crates/gs-core`） |
| 5.2 Python 实现 | 已退役，见 [ADR 005](./adr/005-retire-gs52-python-runtime.md) |

## 已迁移并验证

| 插件 | 分层 | 验证方式 |
|---|---|---|
| `navigator` | T1 声明式 | 前门 E2E，目录路径展开 `$HOME` |
| `alias` | T2 | 只读检查 + 检测来源 |
| `dotfiles` | T2 | 隔离 `$HOME` 下真装/备份/恢复 |
| `devenv` | T2 | 假 brew/apt 执行器验证真实参数 |
| `grep` | T2 | 检索无 shell 选项注入 |
| `spider` | T2 | URL 白名单与输出边界 |
| `multirepo` | T2 | 本地裸仓库真实 clone + plan/apply |
| `sync` | T2 | 临时 Git 仓库到目标目录真实复制 |
| `system` | T2 | 镜像源/代理 dry-run 与主题枚举 |
| `vps` | T2 | 8 条命令，写操作需 `--dry-run`/`--yes` |
| `identity` | T2 | 生成夹具；包内无任何私钥/密钥 |
| `android` | T2 | 只读命令真机验证；危险操作保持 dry-run |
| `vscode` | T2 | 假 code 执行器，验证 launch 参数 |

## 私有插件

`sgm` 与 `flyme` 的**代码**也不进公开仓库与发布包，只存在于 `custom/userspace/<名字>/`
（`custom/` 被 `.gitignore` 排除）。安装时由 `scripts/install_gs.sh` 复制进已安装树的
`plugins/`，本机 `gs` 照常可用；第三方拿到的发布包不含它们。

## 5.2 的处置

`src/gscripts/`（约 22k 行）、`tests/`（约 23k 行）、`scripts/setup.py`、
`scripts/audit_command_parity.py`、`pyproject.toml`、`pytest.ini`、各插件的
`plugin.json`/`plugin.py`/`plugin.sh`/`commands.json` 以及 `plugins/menubar/`
已从 `develop`/`main` 删除。

代码仍在 git 历史中；需要对照时用

```bash
git log --oneline -1 --diff-filter=D -- src/gscripts
git show <sha>:src/gscripts/cli/main.py | head
```

`gs plugin migrate <目录>` 仍可把第三方的旧 `plugin.json` 转成 `plugin.toml`。

## 验收

```bash
cd rust && cargo test --workspace        # Rust 单元 + 集成
bash scripts/verify_gs.sh                # 端到端（先构建 + stage）
python3 scripts/audit_plugins.py         # 逐插件清单/元数据/冒烟
python3 scripts/verify_package.py --root <打包目录> --target <target>
```

`verify_gs.sh` 覆盖：manifest 数量与版本一致、每个插件 `plugin info` 可渲染、
各组可聚焦、契约命令存在、隔离安装/卸载循环、bash/zsh/fish 集成。
