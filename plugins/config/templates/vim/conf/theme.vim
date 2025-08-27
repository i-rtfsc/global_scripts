" 设置黑色背景
set background=dark

" 允许 256 色
set t_Co=256

" 开启真彩色
if has("termguicolors")
    " enable true color
    set termguicolors
endif

" 设置颜色主题，会在所有 runtimepaths 的 colors 目录寻找同名配置
"color rakr
colorscheme sublime
