# winscope

# 背景

设想一下，假如我们又如下场景，一个闪黑一瞬间的问题，正常我们看到黑屏冻屏问题，是不是时刻想到是要来dumpsys SurfaceFlinger和dumpsys window windows相关的信息来辅助我们分析问题，但奈何这个是个瞬时问题。。。我们dumpsys很难抓住那一瞬间，而且即使抓到了黑一瞬间的，我们有时候分析也要又黑屏前一帧后一帧相关等才可以分析进一步原因。

所以在开发过程中，经常会遇到各种各样的窗口问题，比如动画异常、窗口异常、闪屏、闪黑、黑屏、错位显示…

对于这些问题，添加日志，调试分析代码等手段去解决，但这些 UI 问题往往出现在一瞬间，很难把握出现的时机，录制下来的日志往往也是巨大的，从海量的日志中提取有效的信息是一个枯燥且繁琐的事情，而且也根本没有办法把显示时间戳和日志时间戳完全对好。

Android 也意识到了这个问题，WinScope 的出现有效的帮助我们跟踪窗口和显示问题。它向开发者提供一个可视化的工具，让开发者能使用工具跟踪整个界面的变化过程。

# 如何使用

## 手机

1. 设置->开发者选项->快捷设置开发者功能块->Winscope跟踪
2. 下拉 systemui 快捷菜单打开

## 脚本

1. 打开 html 文件
2. 运行 winscope_proxy.py

> 代码在 development/tools/winscope