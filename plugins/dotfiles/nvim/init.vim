" ============================================
" Modern Neovim Configuration
" Global Scripts - Neovim Configuration
" ============================================
"
" This config uses Lua for modern Neovim features
" Main configuration is in gs-runtime/lua/init.lua
"
" Features:
" - LSP support for code navigation and completion
" - Treesitter for better syntax highlighting
" - Telescope for fuzzy finding
" - File explorer
" - Auto-completion
" - Git integration
" - And more...

" 添加 gs-runtime 到 Lua 模块搜索路径
lua << EOF
local runtime_path = vim.fn.stdpath('config') .. '/gs-runtime'
package.path = runtime_path .. '/lua/?.lua;' .. package.path
EOF

" Load main Lua configuration
lua require('init')
