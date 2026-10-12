# Quick start

## 1. Check the install

```bash
gs version
gs doctor
```

`doctor` reports whether manifests are valid, entries exist, the plugin runtime is
available and shell integration is referenced.

## 2. Learn the three entry points

```bash
gs help                  # front-door commands
gs plugin list           # plugins and command counts
gs plugin info system    # one plugin's full command surface
```

The shape is always:

```
gs <plugin> <verb> [object] [args]
```

Dotted sub-commands and space-separated words are equivalent:

```bash
gs android device logcat        # same as gs android device.logcat
gs system proxy status
```

## 3. Try a few read-only commands

```bash
gs navigator list               # directory navigation table
gs system proxy status          # proxy state
gs android device devices       # connected devices (needs adb)
gs dotfiles status nvim         # diff between dotfiles and $HOME
gs identity ssh status          # SSH asset state
```

Destructive work shows you the plan first:

```bash
gs android build build --dry-run
gs system repo tsinghua --dry-run
gs multirepo plan mini-aosp --backend=git
```

Running for real needs an explicit `--yes`. `gs` never escalates privileges; when
root is required it prints the `sudo …` line for you.

## 4. Enable completion and cd integration

```bash
source <(gs shell-init bash)     # bash
source <(gs shell-init zsh)      # zsh
gs shell-init fish > ~/.config/fish/conf.d/gs.fish   # fish

gs completions bash --install    # completion
```

## 5. Machine provisioning

`gs init` walks the step list in `config/init.toml`:

```bash
gs init --list                   # steps and their current state
gs init --dry-run                # check everything, run nothing
gs init base-tools               # one step
gs init --group=mirror           # one group
```

Steps are reported as ready / needs sudo / plugin not written yet. Sudo steps only
print the command for you to run.

## 6. Next

- Writing plugins: [plugin development](./plugin-development-en.md) + [protocol](../protocol.md)
- Internals: [architecture](./architecture-en.md)
- Common questions: [FAQ](./faq-en.md)
