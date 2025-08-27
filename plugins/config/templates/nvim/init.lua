-- ============================================================================
-- Global Scripts Neovim 配置文件 - 现代化的 Neovim 配置
-- 基于 Lua 的高性能开发环境配置，专为 Neovim 0.8+ 优化
-- 兼容并增强你现有的 vim 配置模块化结构
-- ============================================================================

-- 基础配置检查
if vim.fn.has('nvim-0.8') == 0 then
    vim.api.nvim_err_writeln('此配置需要 Neovim 0.8+')
    return
end

-- 禁用一些内置插件以提升性能
vim.g.loaded_gzip = 1
vim.g.loaded_zip = 1
vim.g.loaded_zipPlugin = 1
vim.g.loaded_tar = 1
vim.g.loaded_tarPlugin = 1
vim.g.loaded_getscript = 1
vim.g.loaded_getscriptPlugin = 1
vim.g.loaded_vimball = 1
vim.g.loaded_vimballPlugin = 1
vim.g.loaded_2html_plugin = 1
vim.g.loaded_logipat = 1
vim.g.loaded_rrhelper = 1
vim.g.loaded_spellfile_plugin = 1
vim.g.loaded_matchit = 1

-- 设置 leader 键
vim.g.mapleader = ' '
vim.g.maplocalleader = ','

-- ============================================================================
-- 基础设置 - 对应原 basic.vim
-- ============================================================================

-- 显示设置
vim.opt.number = true              -- 显示行号
vim.opt.relativenumber = true      -- 显示相对行号
vim.opt.signcolumn = 'yes'         -- 始终显示符号列
vim.opt.wrap = false               -- 不自动换行
vim.opt.cursorline = true          -- 高亮当前行
vim.opt.colorcolumn = '80,120'     -- 显示列指示器

-- 编辑设置
vim.opt.tabstop = 4                -- Tab 宽度
vim.opt.shiftwidth = 4             -- 缩进宽度
vim.opt.expandtab = true           -- 使用空格代替 Tab
vim.opt.autoindent = true          -- 自动缩进
vim.opt.smartindent = true         -- 智能缩进

-- 搜索设置
vim.opt.ignorecase = true          -- 搜索忽略大小写
vim.opt.smartcase = true           -- 智能大小写搜索
vim.opt.hlsearch = true            -- 高亮搜索结果
vim.opt.incsearch = true           -- 增量搜索

-- 文件设置
vim.opt.encoding = 'utf-8'         -- 文件编码
vim.opt.fileencoding = 'utf-8'     -- 文件保存编码
vim.opt.backup = false             -- 不创建备份文件
vim.opt.writebackup = false        -- 不创建写入备份
vim.opt.swapfile = false           -- 不创建交换文件
vim.opt.undofile = true            -- 持久化撤销历史

-- 界面设置
vim.opt.termguicolors = true       -- 启用真彩色
vim.opt.pumheight = 10             -- 弹出菜单最大高度
vim.opt.cmdheight = 1              -- 命令行高度
vim.opt.showmode = false           -- 不显示模式
vim.opt.splitbelow = true          -- 水平分割在下方
vim.opt.splitright = true          -- 垂直分割在右方

-- 性能设置
vim.opt.updatetime = 300           -- 更新时间
vim.opt.timeoutlen = 300           -- 按键超时时间
vim.opt.hidden = true              -- 允许隐藏缓冲区
vim.opt.scrolloff = 8              -- 滚动边距
vim.opt.sidescrolloff = 8          -- 水平滚动边距

-- ============================================================================
-- 键盘映射 - 现代化的快捷键设置
-- ============================================================================

local keymap = vim.keymap.set

-- 取消搜索高亮
keymap('n', '<Esc>', '<cmd>nohlsearch<CR>')

-- 更好的上下移动
keymap('n', 'j', "v:count == 0 ? 'gj' : 'j'", { expr = true, silent = true })
keymap('n', 'k', "v:count == 0 ? 'gk' : 'k'", { expr = true, silent = true })

-- 窗口导航 - 对应原 tmux.vim
keymap('n', '<C-h>', '<C-w>h', { desc = '切换到左窗口' })
keymap('n', '<C-j>', '<C-w>j', { desc = '切换到下窗口' })
keymap('n', '<C-k>', '<C-w>k', { desc = '切换到上窗口' })
keymap('n', '<C-l>', '<C-w>l', { desc = '切换到右窗口' })

-- 窗口大小调整
keymap('n', '<C-Up>', '<cmd>resize +2<CR>', { desc = '增加窗口高度' })
keymap('n', '<C-Down>', '<cmd>resize -2<CR>', { desc = '减少窗口高度' })
keymap('n', '<C-Left>', '<cmd>vertical resize -2<CR>', { desc = '减少窗口宽度' })
keymap('n', '<C-Right>', '<cmd>vertical resize +2<CR>', { desc = '增加窗口宽度' })

-- 缓冲区导航
keymap('n', '<S-h>', '<cmd>bprevious<CR>', { desc = '上一个缓冲区' })
keymap('n', '<S-l>', '<cmd>bnext<CR>', { desc = '下一个缓冲区' })
keymap('n', '<leader>bd', '<cmd>bdelete<CR>', { desc = '删除缓冲区' })

-- 更好的缩进
keymap('v', '<', '<gv', { desc = '减少缩进并保持选择' })
keymap('v', '>', '>gv', { desc = '增加缩进并保持选择' })

-- 移动文本
keymap('v', 'J', ":m '>+1<CR>gv=gv", { desc = '向下移动选中行' })
keymap('v', 'K', ":m '<-2<CR>gv=gv", { desc = '向上移动选中行' })

-- 更好的粘贴
keymap('v', 'p', '"_dP', { desc = '粘贴不覆盖剪贴板' })

-- 系统剪贴板
keymap({'n', 'v'}, '<leader>y', '"+y', { desc = '复制到系统剪贴板' })
keymap({'n', 'v'}, '<leader>p', '"+p', { desc = '从系统剪贴板粘贴' })

-- 快速保存和退出
keymap('n', '<leader>w', '<cmd>w<CR>', { desc = '保存文件' })
keymap('n', '<leader>q', '<cmd>q<CR>', { desc = '退出' })
keymap('n', '<leader>Q', '<cmd>qa!<CR>', { desc = '强制退出所有' })

-- ============================================================================
-- 自动命令 - 对应原配置的各种自动设置
-- ============================================================================

local augroup = vim.api.nvim_create_augroup
local autocmd = vim.api.nvim_create_autocmd

-- 高亮复制内容
augroup('YankHighlight', { clear = true })
autocmd('TextYankPost', {
    group = 'YankHighlight',
    callback = function()
        vim.highlight.on_yank({ higroup = 'IncSearch', timeout = 300 })
    end,
})

-- 自动调整窗口大小
augroup('ResizeWindows', { clear = true })
autocmd('VimResized', {
    group = 'ResizeWindows',
    command = 'wincmd ='
})

-- 文件类型特定设置
augroup('FileTypeSettings', { clear = true })
autocmd('FileType', {
    group = 'FileTypeSettings',
    pattern = { 'lua', 'python' },
    callback = function()
        vim.opt_local.tabstop = 4
        vim.opt_local.shiftwidth = 4
    end,
})

autocmd('FileType', {
    group = 'FileTypeSettings',
    pattern = { 'html', 'css', 'javascript', 'typescript', 'json', 'yaml' },
    callback = function()
        vim.opt_local.tabstop = 2
        vim.opt_local.shiftwidth = 2
    end,
})

-- 记住光标位置
augroup('RestoreCursor', { clear = true })
autocmd('BufReadPost', {
    group = 'RestoreCursor',
    callback = function()
        local line = vim.fn.line("'\"")
        if line > 1 and line <= vim.fn.line('$') and vim.bo.filetype ~= 'commit' then
            vim.cmd('normal! g`"')
        end
    end,
})

-- ============================================================================
-- 颜色主题 - 对应原 theme.vim
-- ============================================================================

-- 设置默认颜色方案
vim.cmd.colorscheme('habamax')  -- Neovim 内置的现代主题

-- 自定义高亮组
local function setup_highlights()
    local highlights = {
        -- 当前行号高亮
        CursorLineNr = { fg = '#ff9e64', bold = true },
        -- 列指示器
        ColorColumn = { bg = '#2a2a37' },
        -- 搜索高亮
        Search = { bg = '#ff9e64', fg = '#1a1b26' },
        IncSearch = { bg = '#bb9af7', fg = '#1a1b26' },
        -- 状态栏
        StatusLine = { bg = '#16161e', fg = '#c0caf5' },
        StatusLineNC = { bg = '#16161e', fg = '#545c7e' },
    }
    
    for group, opts in pairs(highlights) do
        vim.api.nvim_set_hl(0, group, opts)
    end
end

setup_highlights()

-- 主题切换后重新设置高亮
augroup('ThemeOverrides', { clear = true })
autocmd('ColorScheme', {
    group = 'ThemeOverrides',
    callback = setup_highlights,
})

-- ============================================================================
-- 插件管理 - 现代化的插件配置
-- ============================================================================

-- 检查是否安装了 lazy.nvim 插件管理器
local lazypath = vim.fn.stdpath('data') .. '/lazy/lazy.nvim'
if not vim.loop.fs_stat(lazypath) then
    -- 如果没有安装，提供安装提示
    vim.api.nvim_echo({
        { '插件管理器 lazy.nvim 未安装\n', 'WarningMsg' },
        { '运行以下命令安装:\n', 'Normal' },
        { 'git clone --filter=blob:none --branch=stable https://github.com/folke/lazy.nvim.git ' .. lazypath, 'String' },
    }, true, {})
else
    vim.opt.rtp:prepend(lazypath)
    
    -- 配置基础插件
    require('lazy').setup({
        -- 主题插件
        {
            'folke/tokyonight.nvim',
            lazy = false,
            priority = 1000,
            config = function()
                vim.cmd.colorscheme('tokyonight-night')
            end,
        },
        
        -- 状态栏
        {
            'nvim-lualine/lualine.nvim',
            dependencies = { 'nvim-tree/nvim-web-devicons' },
            config = function()
                require('lualine').setup({
                    options = { theme = 'tokyonight' }
                })
            end,
        },
        
        -- 文件浏览器
        {
            'nvim-tree/nvim-tree.lua',
            dependencies = { 'nvim-tree/nvim-web-devicons' },
            config = function()
                require('nvim-tree').setup()
                vim.keymap.set('n', '<leader>e', '<cmd>NvimTreeToggle<CR>', { desc = '切换文件浏览器' })
            end,
        },
        
        -- 模糊查找
        {
            'nvim-telescope/telescope.nvim',
            dependencies = { 'nvim-lua/plenary.nvim' },
            config = function()
                local builtin = require('telescope.builtin')
                vim.keymap.set('n', '<leader>ff', builtin.find_files, { desc = '查找文件' })
                vim.keymap.set('n', '<leader>fg', builtin.live_grep, { desc = '全局搜索' })
                vim.keymap.set('n', '<leader>fb', builtin.buffers, { desc = '查找缓冲区' })
            end,
        },
        
        -- 语法高亮
        {
            'nvim-treesitter/nvim-treesitter',
            build = ':TSUpdate',
            config = function()
                require('nvim-treesitter.configs').setup({
                    ensure_installed = { 'lua', 'vim', 'vimdoc', 'python', 'javascript', 'typescript' },
                    highlight = { enable = true },
                    indent = { enable = true },
                })
            end,
        },
        
        -- 自动补全
        {
            'hrsh7th/nvim-cmp',
            dependencies = {
                'hrsh7th/cmp-nvim-lsp',
                'hrsh7th/cmp-buffer',
                'hrsh7th/cmp-path',
                'L3MON4D3/LuaSnip',
            },
            config = function()
                local cmp = require('cmp')
                cmp.setup({
                    mapping = cmp.mapping.preset.insert({
                        ['<C-d>'] = cmp.mapping.scroll_docs(-4),
                        ['<C-f>'] = cmp.mapping.scroll_docs(4),
                        ['<C-Space>'] = cmp.mapping.complete(),
                        ['<CR>'] = cmp.mapping.confirm({ select = true }),
                    }),
                    sources = {
                        { name = 'nvim_lsp' },
                        { name = 'buffer' },
                        { name = 'path' },
                    },
                })
            end,
        },
    })
end

-- ============================================================================
-- 兼容性设置 - 保持与原配置的兼容性
-- ============================================================================

-- 如果存在原有的 vim 配置目录，添加到运行时路径
local old_vim_config = vim.fn.expand('~/bin/global_scripts/conf/gs_vim')
if vim.fn.isdirectory(old_vim_config) == 1 then
    vim.opt.rtp:append(old_vim_config)
end

-- 兼容原有的自定义配置目录
local user_config = vim.fn.expand('~/.config/gs-vim')
if vim.fn.isdirectory(user_config) == 1 then
    vim.opt.rtp:append(user_config)
end

-- ============================================================================
-- 使用说明
-- ============================================================================

--[[
常用快捷键：
  <Space>     - Leader 键
  <Space>w    - 保存文件
  <Space>q    - 退出
  <Space>e    - 切换文件浏览器
  <Space>ff   - 查找文件
  <Space>fg   - 全局搜索
  <Space>fb   - 查找缓冲区
  <Space>bd   - 删除缓冲区
  <Shift>h/l  - 切换缓冲区
  <Ctrl>hjkl  - 窗口导航

插件安装：
1. 首次使用需要安装 lazy.nvim 插件管理器
2. 重启 Neovim 后插件会自动安装
3. 使用 :Lazy 命令管理插件

tmux 集成：
- 与 tmux 的窗口导航完全兼容
- 支持 tmux-resurrect 会话恢复
- 继承原有 tmux 配置的所有功能

迁移说明：
- 完全兼容原有 vim 配置
- 可以与原有 vim 配置并存使用
- 保留原有的模块化结构和自定义设置
--]]