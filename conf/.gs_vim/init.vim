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

" 将 gs_vim 目录加入 runtimepath
exec 'set rtp+='.s:home

" 将 ~/.gs_vim 目录加入 runtimepath (有时候 vim 不会自动帮你加入）
set rtp+=~/.gs_vim


"----------------------------------------------------------------------
" 模块加载
"----------------------------------------------------------------------

" 加载基础配置
LoadScript init/basic.vim

" 加载扩展配置
LoadScript init/config.vim

" 设定 tabsize
LoadScript init/tabsize.vim

" 界面样式
LoadScript init/style.vim

" 自定义按键
LoadScript init/keymaps.vim

if has('mac')
    " 主题
    LoadScript init/theme.vim
endif
