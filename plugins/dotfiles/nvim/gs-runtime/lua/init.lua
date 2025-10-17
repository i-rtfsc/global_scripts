-- ============================================
-- Modern Neovim Configuration - Main Entry Point
-- ============================================

-- Load configuration modules
require('options')    -- Editor options
require('keymaps')    -- Key mappings
require('plugins')    -- Plugin management with lazy.nvim

-- Additional global settings
vim.g.loaded_netrw = 1
vim.g.loaded_netrwPlugin = 1

-- 主题由 plugins.lua 统一管理，无需在此设置
-- 如需更改主题，请编辑 plugins.lua 文件

-- Auto-format on save (optional, can be enabled per filetype)
-- vim.api.nvim_create_autocmd("BufWritePre", {
--   pattern = "*",
--   callback = function()
--     vim.lsp.buf.format({ async = false })
--   end,
-- })
