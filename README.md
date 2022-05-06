# global scripts

# 依赖zsh、oyz
如果不想用zsh，也可以使用该工程。但建议配合zsh使用更佳。
## 安装zsh
```bash
sudo apt insall zsh
or
brew install zsh
```
## 安装oyz
```bash
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```
> https://github.com/ohmyzsh/ohmyzsh

## 配置
在.zshrc里source env.sh文件即可，比如我的工程目录在/Users/solo/code/github/global_scripts
```bash
source $HOME/code/github/global_scripts/env.sh
```
> 若没安装zsh，则需要改成在.bashrc中source env.sh。注释掉env.sh中source zsh_theme.sh这一行。

# 脚本能力
## android_build.sh
android源码编译快捷键命令，如全编、ninja单编等。
> 暂时用到这些命令，后续有常用的再补充
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/8350] ➤ [2022-04-29 17:02:11]
╰─(py39tf2.x) ❯❯❯❯❯❯ gs_android_build
gs_android_build             gs_android_build_make        gs_android_build_ninja       gs_android_build_ota         gs_android_build_system      gs_android_build_system_ext  gs_android_build_vendor
```
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/8450] ➤ [2022-04-29 17:03:55]
╰─(Ppy39tf2.x) ❯❯❯❯❯❯ gs_android_build_ninja
Trying dependencies-only mode on a non-existing device tree?

1. bx-framework
2. framework
3. services
4. J007Service
5. com.journeyOS.J007engine.hidl@1.0-service
6. UMS
7. UMSTest
8. AiService
9. update_engine
10. surfaceflinger
11. android.hardware.power-service
12. SystemUI
13. Settings
Which would you like? [ com.journeyOS.J007engine.hidl@1.0-service ]
```

## android_grep.sh
android源码目录下grep快速查找代码
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/8450] ➤ [2022-04-29 17:05:24]
╰─(py39tf2.x) ❯❯❯❯❯❯ gs_aosp_help
- gs_aosp_cgrep:      Greps on all local C/C++ files.
- gs_aosp_ggrep:      Greps on all local Gradle files.
- gs_aosp_gogrep:     Greps on all local Go files.
- gs_aosp_jgrep:      Greps on all local Java files.
- gs_aosp_ktgrep:     Greps on all local Kotlin files.
- gs_aosp_resgrep:    Greps on all local res/*.xml files.
- gs_aosp_mangrep:    Greps on all local AndroidManifest.xml files.
- gs_aosp_mgrep:      Greps on all local Makefiles and *.bp files.
- gs_aosp_owngrep:    Greps on all local OWNERS files.
- gs_aosp_rsgrep:     Greps on all local Rust files.
- gs_aosp_sepgrep:    Greps on all local sepolicy files.
- gs_aosp_sgrep:      Greps on all local source files.
```


## adb.sh
adb快捷键命令
> 暂时用到这些命令，后续有常用的再补充
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/8350] ➤ [2022-04-29 17:06:17]
╰─(py39tf2.x) ❯❯❯❯❯❯ gs_adb_
gs_adb_dispaysync          gs_adb_imei                gs_adb_key_home            gs_adb_log_grep            gs_adb_show_3rd_app
gs_adb_hidden_api_disable  gs_adb_key                 gs_adb_key_menu            gs_adb_ps_grep             gs_adb_show_system_app
gs_adb_hidden_api_enable   gs_adb_key_back            gs_adb_kill_grep           gs_adb_screencap           gs_adb_systrace
```

## android_push.sh
push一些常用模块

## zsh自定义主题
用户名、ip地址、当前目录绝对路径、当前时间
git信息（分支、是否修改等）
如果在conda环境中，还显示conda信息。
> 主题是有一些颜色的，这里文本显示不出来。

已经安装conda时的主题：
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/github/global_scripts] ➤ [2022-04-29 17:07:25]
╰─(py39tf2.x) ❯❯❯❯❯❯                                                                                                                                                                            git:(main*)
```
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/github] ➤ [2022-04-29 17:07:51]
╰─(py39tf2.x) ❯❯❯❯❯❯
```

未安装conda时的主题：
```bash
╭─[solo@10.164.118.252] ➤ [/home/solo/code/lineage] ➤ [2022-04-29 17:09:07]
╰─(Python2.7.18) ❯❯❯❯❯❯
```

## gerrit提交脚本
如果是提交代码到gerrit，在终端执行gerrit.py -b branch。不输入分支信息则默认master分支。

## 查询天气脚本
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/github] ➤ [2022-04-29 17:10:40]
╰─(py39tf2.x) ❯❯❯❯❯❯ forecast.py
/Users/solo/code/github/global_scripts/forecast.py
curl -H "Accept-Language: zh" wttr.in/shanghai+pudong
天气预报： shanghai+pudong

     \  /       局部多云
   _ /"".-.     +15(14) °C
     \_(   ).   ↓ 19 km/h
     /(___(__)  10 km
                0.0 mm
                                                       ┌─────────────┐
┌──────────────────────────────┬───────────────────────┤4月29日星期五├───────────────────────┬──────────────────────────────┐
│             早上             │             中午      └──────┬──────┘       傍晚            │             夜间             │
├──────────────────────────────┼──────────────────────────────┼──────────────────────────────┼──────────────────────────────┤
│               阴天           │               阴天           │               多云           │    \  /       局部多云       │
│      .--.     +14(12) °C     │      .--.     +15(13) °C     │      .--.     15 °C          │  _ /"".-.     +14(13) °C     │
│   .-(    ).   ↓ 17-21 km/h   │   .-(    ).   ↓ 17-21 km/h   │   .-(    ).   ↓ 10-12 km/h   │    \_(   ).   ↓ 9-12 km/h    │
│  (___.__)__)  10 km          │  (___.__)__)  10 km          │  (___.__)__)  10 km          │    /(___(__)  10 km          │
│               0.0 mm | 0%    │               0.0 mm | 0%    │               0.0 mm | 0%    │               0.0 mm | 0%    │
└──────────────────────────────┴──────────────────────────────┴──────────────────────────────┴──────────────────────────────┘
                                                       ┌─────────────┐
┌──────────────────────────────┬───────────────────────┤4月30日星期六├───────────────────────┬──────────────────────────────┐
│             早上             │             中午      └──────┬──────┘       傍晚            │             夜间             │
├──────────────────────────────┼──────────────────────────────┼──────────────────────────────┼──────────────────────────────┤
│               多云           │    \  /       局部多云       │    \  /       局部多云       │    \  /       局部多云       │
│      .--.     14 °C          │  _ /"".-.     17 °C          │  _ /"".-.     16 °C          │  _ /"".-.     14 °C          │
│   .-(    ).   ↙ 8-10 km/h    │    \_(   ).   ↙ 6-8 km/h     │    \_(   ).   ↙ 9-11 km/h    │    \_(   ).   ↓ 8-10 km/h    │
│  (___.__)__)  10 km          │    /(___(__)  10 km          │    /(___(__)  10 km          │    /(___(__)  10 km          │
│               0.0 mm | 0%    │               0.0 mm | 0%    │               0.0 mm | 0%    │               0.0 mm | 0%    │
└──────────────────────────────┴──────────────────────────────┴──────────────────────────────┴──────────────────────────────┘
                                                       ┌─────────────┐
┌──────────────────────────────┬───────────────────────┤5月01日星期日├───────────────────────┬──────────────────────────────┐
│             早上             │             中午      └──────┬──────┘       傍晚            │             夜间             │
├──────────────────────────────┼──────────────────────────────┼──────────────────────────────┼──────────────────────────────┤
│    \  /       局部多云       │    \  /       局部多云       │     \   /     晴天           │     \   /     晴朗           │
│  _ /"".-.     16 °C          │  _ /"".-.     20 °C          │      .-.      19 °C          │      .-.      16 °C          │
│    \_(   ).   ↘ 8-9 km/h     │    \_(   ).   ↘ 10-12 km/h   │   ― (   ) ―   ← 7-8 km/h     │   ― (   ) ―   ↖ 7-10 km/h    │
│    /(___(__)  10 km          │    /(___(__)  10 km          │      `-’      10 km          │      `-’      10 km          │
│               0.0 mm | 0%    │               0.0 mm | 0%    │     /   \     0.0 mm | 0%    │     /   \     0.0 mm | 0%    │
└──────────────────────────────┴──────────────────────────────┴──────────────────────────────┴──────────────────────────────┘
地点: 浦东新区, 上海市, 中国 [31.1173327,121.6904884]

关注 @igor_chubin 获取 wttr.in 动态
```

## other
- common_alias.sh : 常用的alias
- private_alias.sh : 私人的一些alias

# git
## 快捷命令
```bash
a = add
b = branch
c = commit
d = diff
f = fetch
g = grep
l = log
m = merge
o = checkout
p = pull
r = remote
s = status
w = whatchanged

ap = add --patch
be = branch --edit-description
ci = commit --interactive
ds = diff --staged
lg = log --graph
ss = status --short
```

# vim
轻量级 Vim 配置框架，全中文注释。

## 基础配置
- init.vim: 配置入口，设置 runtimepath 检测脚本路径，加载其他脚本。
- basic.vim: 所有人都能同意的基础配置，去除任何按键和样式定义，保证能用于 tiny 模式（没有 +eval）。
- config.vim: 支持 +eval 的非 tiny 配置，初始化 ALT 键支持，功能键键盘码，备份，终端兼容等
- tabsize.vim: 制表符宽度，是否展开空格等，因为个人差异太大，单独一个文件好更改。
- style.vim: 状态栏，更紧凑的标签栏文字等和显示相关。
- keymaps.vim: 快捷键定义。
- theme.vim: 色彩主题，高亮优化(mac系统下打开此功能)。

## 高级配置
颜色配置：在colors目录（都是网上下载的配置），下载后在theme.vim更新主题即可。