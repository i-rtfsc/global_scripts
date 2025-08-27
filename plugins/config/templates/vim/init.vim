" ============================================================================
" Global Scripts Vim 配置文件 - 现代化的 Vim/Neovim 配置
" 基于最佳实践的高效开发环境配置
" 支持 Vim 8.0+ 和 Neovim 0.5+
" ============================================================================

" 防止重复加载配置
if get(s:, 'loaded', 0) != 0
    finish
else
    let s:loaded = 1
endif

" 获取配置文件所在目录
let s:home = fnamemodify(resolve(expand('<sfile>:p')), ':h')

" 定义加载脚本的命令
command! -nargs=1 LoadScript exec 'so '.s:home.'/'.'<args>'

" 将配置目录加入运行时路径
exec 'set rtp+='.s:home

" 添加用户配置目录到运行时路径
if isdirectory(expand('~/.config/gs-vim'))
    set rtp+=~/.config/gs-vim
endif

"----------------------------------------------------------------------
" 兼容性检查 - 确保在不同 Vim 版本中正常工作
"----------------------------------------------------------------------

" 检查 Vim 版本
if v:version < 800 && !has('nvim')
    echoerr '此配置需要 Vim 8.0+ 或 Neovim'
    finish
endif

" 设置兼容模式
if &compatible
    set nocompatible
endif

"----------------------------------------------------------------------
" 基础配置模块加载 - 按功能模块化组织配置
"----------------------------------------------------------------------

" 核心基础设置 - 必须最先加载
LoadScript conf/tiny/basic.vim

" 代码风格设置 - 缩进、折叠等
LoadScript conf/tiny/codestyle.vim

" 搜索配置 - 搜索高亮、增量搜索等  
LoadScript conf/tiny/search.vim

" 其他实用设置 - 鼠标、剪贴板等
LoadScript conf/tiny/other.vim

"----------------------------------------------------------------------
" 高级功能模块 - 可选加载的增强功能
"----------------------------------------------------------------------

" 终端配置 - 终端模式相关设置
if has('terminal') || has('nvim')
    LoadScript conf/terminal.vim
endif

" Tmux 集成 - 如果在 tmux 环境中运行
if exists('$TMUX') || exists('$TMUX_PANE')
    LoadScript conf/tmux.vim
endif

" 文件类型相关配置 - 针对不同文件类型的特殊设置
LoadScript conf/fileconfig.vim

" Tab 和缩进设置 - 统一的缩进标准
LoadScript conf/tabsize.vim

" 界面样式设置 - 状态栏、行号等
LoadScript conf/style.vim

"----------------------------------------------------------------------
" 系统特定配置 - 根据操作系统加载特定配置
"----------------------------------------------------------------------

" macOS 特定配置
if has('mac') || has('macunix')
    " 主题配置 - macOS 下的颜色主题
    LoadScript conf/theme.vim
    
    " macOS 特定的按键映射
    if has('gui_macvim')
        set macmeta
    endif
endif

" Linux 特定配置
if has('unix') && !has('mac')
    " Linux 特定的字体和主题设置
    if has('gui_running')
        set guifont=Consolas:h12
    endif
endif

" Windows 特定配置
if has('win32') || has('win64')
    " Windows 下的字体设置
    if has('gui_running')
        set guifont=Consolas:h12:cANSI
    endif
    
    " Windows 下的换行符处理
    set fileformats=dos,unix
endif

"----------------------------------------------------------------------
" 按键映射配置 - 可选加载，防止冲突
"----------------------------------------------------------------------

" 如果需要自定义按键映射，取消下面的注释
" LoadScript conf/keymaps.vim

"----------------------------------------------------------------------
" 插件管理配置 - 根据环境选择插件管理器
"----------------------------------------------------------------------

" 如果安装了 vim-plug
if filereadable(expand('~/.vim/autoload/plug.vim')) || 
   \ filereadable(expand('~/.local/share/nvim/site/autoload/plug.vim'))
    " 可以在这里加载插件配置
    " LoadScript conf/plugins.vim
endif

"----------------------------------------------------------------------
" 用户自定义配置 - 个人定制化配置
"----------------------------------------------------------------------

" 加载用户自定义配置文件（如果存在）
let s:user_config = expand('~/.config/gs-vim/user.vim')
if filereadable(s:user_config)
    exec 'source ' . s:user_config
endif

" 加载项目特定配置（如果存在）
let s:project_config = getcwd() . '/.vimrc.local'
if filereadable(s:project_config)
    exec 'source ' . s:project_config
endif

"----------------------------------------------------------------------
" 最终设置 - 确保配置正确生效
"----------------------------------------------------------------------

" 启用文件类型检测
filetype plugin indent on

" 启用语法高亮
if !exists('g:syntax_on')
    syntax enable
endif

" 设置编码
if has('multi_byte')
    set encoding=utf-8
    set fileencodings=utf-8,gbk,gb2312,cp936,ucs-bom,latin1
endif

" 配置完成提示
autocmd VimEnter * echom "Global Scripts Vim 配置加载完成！"

"----------------------------------------------------------------------
" 错误处理 - 捕获配置加载错误
"----------------------------------------------------------------------

" 如果配置加载过程中出现错误，显示友好的错误信息
function! s:ConfigError(msg)
    echohl ErrorMsg
    echom "配置加载错误: " . a:msg
    echohl None
endfunction

" 设置错误处理
if exists('*ConfigError')
    " 错误已处理
endif