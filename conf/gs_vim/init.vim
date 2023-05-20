" 防止重复加载
if get(s:, 'loaded', 0) != 0
	finish
else
	let s:loaded = 1
endif

" 取得本文件所在的目录
let s:home = fnamemodify(resolve(expand('<sfile>:p')), ':h')

" 定义一个命令用来加载文件
command! -nargs=1 LoadScript exec 'so '.s:home.'/'.'<args>'

" 将 vim-init 目录加入 runtimepath
exec 'set rtp+='.s:home

" 将 ~/.gs_vim 目录加入 runtimepath (有时候 vim 不会自动帮你加入）
set rtp+=~/.gs_vim

"----------------------------------------------------------------------
" 模块加载
"----------------------------------------------------------------------

" 基础设置
LoadScript conf/tiny/basic.vim

" 代码格式
LoadScript conf/tiny/codestyle.vim

" 搜索设置
LoadScript conf/tiny/search.vim

" 其他设置
LoadScript conf/tiny/other.vim

" tmux配置
LoadScript conf/tmux.vim

" terminal设置
LoadScript conf/terminal.vim

" 文件相关配置
LoadScript conf/fileconfig.vim

" 设定 tabsize
LoadScript conf/tabsize.vim

" 界面样式
LoadScript conf/style.vim

" 自定义按键
" LoadScript conf/keymaps.vim

if has('mac')
    " 主题
    LoadScript conf/theme.vim
endif