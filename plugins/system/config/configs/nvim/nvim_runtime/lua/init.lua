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

-- Set colorscheme (will be installed by lazy.nvim)
vim.cmd([[
  try
    colorscheme tokyonight-night
  catch /^Vim\%((\a\+)\)\=:E185/
    " Colorscheme not found, use default
    colorscheme default
  endtry
]])

-- Auto-format on save (optional, can be enabled per filetype)
-- vim.api.nvim_create_autocmd("BufWritePre", {
--   pattern = "*",
--   callback = function()
--     vim.lsp.buf.format({ async = false })
--   end,
-- })
