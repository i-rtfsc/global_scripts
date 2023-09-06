# tmux 插件

## 下载tpm

```base
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

## 更新 ~/.tmux.conf

使用命令gs_init_tmux更新 ~/.tmux.conf 文件。

每次更新 ~/.tmux.conf 文件都要执行下面命令，才能生效。
```base
tmux source-file ~/.tmux.conf
```

## 首次使用

在tmux环境下，按以下步骤加载.tmux.conf使用到的插件

1. ctrl + b
2. 大写的I
3. 根据提示按esc退出

当前使用到的插件如下：
```base
$ ls ~/.tmux/plugins/
tmux  tmux-continuum  tmux-resurrect  tmux-sensible  tpm
```
> 若 ~/.tmux/plugins/ 文件夹下没有以上插件，会不生效(或者可以会出问题)。