# global scripts

在 ~/.bashrc 里source gs_env.sh文件即可，比如我的工程目录在/Users/solo/code/github/global_scripts
```bash
source $HOME/code/github/global_scripts/gs_env.sh
```
> ~/.bashrc 和 ~/.zshrc 都要 source
> source gs_env.sh 要改成其所在的路径

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
在 ~/.zshrc 里source gs_env.sh文件即可，比如我的工程目录在/Users/solo/code/github/global_scripts
```bash
source $HOME/code/github/global_scripts/gs_env.sh
```
> ~/.bashrc 和 ~/.zshrc 都要 source
> source gs_env.sh 要改成其所在的路径
>
> .zshrc里还配置zsh-autosuggestions 、zsh-syntax-highlighting插件，所以需要下载以下两个工程
> $ git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
> $ git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

# 重要
gs_env.sh文件中，要把 _GS_ROOT_PATH 配置成正确的路径（也就是你下载global_scripts工程的路径）
```bash
_GS_ROOT_PATH="$HOME/code/github/global_scripts"
```

# 脚本能力
## android_build.sh
android源码编译快捷键命令，如全编、ninja单编等。
> 暂时用到这些命令，后续有常用的再补充
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/8350] ➤ [2022-04-29 17:02:11]
╰─(py39tf2.x) ❯❯❯❯❯❯ gs_android_build
gs_android_build              gs_android_build_ninja        gs_android_build_ota          gs_android_build.sh           gs_android_build_system_ext                                                                                                                   
gs_android_build_make         gs_android_build_ninja_clean  gs_android_build_qssi         gs_android_build_system       gs_android_build_vendor
```
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/8450] ➤ [2022-04-29 17:03:55]
╰─(Ppy39tf2.x) ❯❯❯❯❯❯ gs_android_build_ninja
Trying dependencies-only mode on a non-existing device tree?

1. framework
2. framework-minus-apex
3. services
4. libandroid_servers
5. libinputflinger
6. libinputdispatcher
7. libinputreader
8. selinux_policy
9. surfaceflinger
10. update_engine
11. android.hardware.power-service
12. libresourcemanagerservice
13. libaudioflinger
14. libcameraservice
15. com.journeyOS.J007engine.hidl@1.0-service
16. com.journeyOS.J007engine.hidl@1.0
17. J007Service
18. jos-framework
19. jos-services
20. watermark
Which would you like? [ framework ]
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
gs_adb_abx2xml                gs_adb_hidden_api_enable      gs_adb_imei                   gs_adb_j007service_clear      gs_adb_key_back               gs_adb_log_grep               gs_adb_selinux_disable        gs_adb_show_3rd_app                                       
gs_adb_clear_package          gs_adb_i007service_clear      gs_adb_input_disable          gs_adb_j007service_kill       gs_adb_key_home               gs_adb_ps_grep                gs_adb_settings_provider      gs_adb_show_log                                           
gs_adb_dump_version           gs_adb_i007service_kill       gs_adb_input_enable           gs_adb_j007service_log        gs_adb_key_menu               gs_adb_rm_dex2oat             gs_adb_sf_dump_refresh_rate   gs_adb_show_system_app                                    
gs_adb_dump_version_settings  gs_adb_i007service_log        gs_adb_j007engine_kill        gs_adb_j007service_version    gs_adb_kill_grep              gs_adb_screencap              gs_adb_sf_set_refresh_rate    gs_adb_shutdown_emulator                                  
gs_adb_hidden_api_disable     gs_adb_i007service_version    gs_adb_j007engine_log         gs_adb_key                    gs_adb_kill_package           gs_adb_screenrecord           gs_adb_sf_show_refresh_rate   gs_adb_systrace
```

## android_push.sh
```bash
╭─[solo@10.0.12.10] ➤ [/Users/solo/code/8350] ➤ [2022-04-29 17:06:17]
╰─(py39tf2.x) ❯❯❯❯❯❯ gs_android_push_
gs_android_push_ext_framework   gs_android_push_ext_services    gs_android_push_framework       gs_android_push_fwk             gs_android_push_mediaserver     gs_android_push_so                                                                          
gs_android_push_ext_fwk         gs_android_push_flyme_services  gs_android_push_framework_jni   gs_android_push_input           gs_android_push_services        gs_android_push_surfaceflinger
```

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
- tiny文件夹: 所有人都能同意的基础配置（无任何按键和样式定义）。
- fileconfig.vim: 文件相关的配置。
- keymaps.vim: 快捷键定义。
- style.vim: 状态栏，更紧凑的标签栏文字等和显示相关。
- tabsize.vim: 制表符宽度，是否展开空格等，因为个人差异太大，单独一个文件好更改。
- terminal.vim: 终端相关配置。
- theme.vim: 色彩主题，高亮优化(mac系统下打开此功能)。
- tmux.vim: tmux相关配置。

## 色彩配置
颜色配置：在colors目录（都是网上下载的配置），下载后在theme.vim更新颜色主题即可。