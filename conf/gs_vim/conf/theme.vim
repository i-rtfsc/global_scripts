" 设置黑色背景
set background=dark

" 允许 256 色
set t_Co=256

" 开启真彩色
if has("termguicolors")
    " fix bug for vim
    set t_8f=^[[38;2;%lu;%lu;%lum
    set t_8b=^[[48;2;%lu;%lu;%lum

    " enable true color
    set termguicolors
endif

" 设置颜色主题，会在所有 runtimepaths 的 colors 目录寻找同名配置
"color rakr
colorscheme sublime
