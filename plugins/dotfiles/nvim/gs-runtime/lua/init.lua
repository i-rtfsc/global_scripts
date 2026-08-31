-- Global Scripts Configuration
-- Generated automatically - do not edit manually
-- Generated at: 2026-03-23 15:40:42
-- Configuration source: /Users/solo/code/github/global_scripts

-- ============================================
-- Modern Neovim Configuration - Main Entry Point
-- ============================================

if vim.loader and vim.loader.enable then
	vim.loader.enable()
end

-- 在加载插件前关闭 netrw，避免与 nvim-tree 冲突并减少启动开销。
vim.g.loaded_netrw = 1
vim.g.loaded_netrwPlugin = 1

-- Load configuration modules
require('options')    -- Editor options
require('keymaps')    -- Key mappings
require('plugins')    -- Plugin management with lazy.nvim

-- 主题由 plugins.lua 统一管理，无需在此设置
-- 如需更改主题，请编辑 plugins.lua 文件

-- Auto-format on save (optional, can be enabled per filetype)
-- vim.api.nvim_create_autocmd("BufWritePre", {
--   pattern = "*",
--   callback = function()
--     vim.lsp.buf.format({ async = false })
--   end,
-- })
