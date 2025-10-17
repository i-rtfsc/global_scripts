-- ============================================
-- Neovim Options Configuration
-- ============================================

local opt = vim.opt
local g = vim.g

-- ============================================
-- Leader Key
-- ============================================
g.mapleader = " "
g.maplocalleader = " "

-- ============================================
-- General Settings
-- ============================================
opt.mouse = "a"                    -- Enable mouse support
opt.clipboard = "unnamedplus"      -- Use system clipboard
opt.swapfile = false              -- Don't use swapfile
opt.completeopt = "menu,menuone,noselect"  -- Completion options
opt.undofile = true               -- Enable persistent undo
opt.updatetime = 250              -- Faster completion
opt.timeoutlen = 300              -- Time to wait for mapped sequence

-- ============================================
-- UI Settings
-- ============================================
opt.number = true                 -- Show line numbers
opt.relativenumber = false        -- Use absolute line numbers (not relative)
opt.cursorline = true            -- Highlight current line
opt.signcolumn = "yes"           -- Always show sign column
opt.colorcolumn = "100"          -- Show column at 100 characters
opt.wrap = false                 -- Don't wrap lines
opt.scrolloff = 8                -- Keep 8 lines above/below cursor
opt.sidescrolloff = 8            -- Keep 8 columns left/right of cursor
opt.pumheight = 10               -- Max items in popup menu
opt.showmode = false             -- Don't show mode (already in statusline)
opt.showcmd = true               -- Show command in statusline
opt.cmdheight = 1                -- Command line height
opt.laststatus = 3               -- Global statusline
opt.termguicolors = true         -- True color support
opt.list = true                  -- Show invisible characters
opt.listchars = { tab = "» ", trail = "·", nbsp = "␣" }

-- ============================================
-- Editing
-- ============================================
opt.expandtab = true             -- Use spaces instead of tabs
opt.shiftwidth = 4               -- Number of spaces for indentation
opt.tabstop = 4                  -- Number of spaces per tab
opt.softtabstop = 4              -- Number of spaces per tab in insert mode
opt.smartindent = true           -- Smart autoindenting
opt.autoindent = true            -- Copy indent from current line
opt.breakindent = true           -- Wrapped lines continue indentation

-- ============================================
-- Search
-- ============================================
opt.ignorecase = true            -- Ignore case in search
opt.smartcase = true             -- Unless search contains uppercase
opt.hlsearch = true              -- Highlight search results
opt.incsearch = true             -- Show search matches as you type
opt.inccommand = "split"         -- Show substitution preview in split

-- ============================================
-- Splits
-- ============================================
opt.splitbelow = true            -- Horizontal splits below
opt.splitright = true            -- Vertical splits to the right

-- ============================================
-- Performance
-- ============================================
opt.lazyredraw = false           -- Don't redraw while executing macros
opt.synmaxcol = 240              -- Max column for syntax highlight

-- ============================================
-- Folding (with Treesitter)
-- ============================================
opt.foldmethod = "expr"
opt.foldexpr = "nvim_treesitter#foldexpr()"
opt.foldenable = false           -- Don't fold by default
opt.foldlevel = 99

-- ============================================
-- File Encoding
-- ============================================
opt.fileencoding = "utf-8"       -- File encoding
opt.encoding = "utf-8"           -- Internal encoding

-- ============================================
-- Backup and Undo
-- ============================================
opt.backup = false               -- Don't create backup files
opt.writebackup = false          -- Don't create backup before writing
opt.undodir = vim.fn.stdpath("data") .. "/undo"
opt.undofile = true

-- ============================================
-- Spell Check
-- ============================================
opt.spell = false                -- Disable spell check by default
opt.spelllang = "en_us"          -- Spell check language

-- ============================================
-- Wildmenu
-- ============================================
opt.wildmenu = true
opt.wildmode = "longest:full,full"
opt.wildignore = "*.o,*.obj,*~,*.pyc,*.class"

-- ============================================
-- Diff Mode
-- ============================================
opt.diffopt = "vertical,filler,internal,algorithm:histogram,indent-heuristic"

-- ============================================
-- Messages
-- ============================================
opt.shortmess:append("c")        -- Don't show completion messages

-- ============================================
-- Autocommands
-- ============================================

-- Highlight yanked text
vim.api.nvim_create_autocmd("TextYankPost", {
  group = vim.api.nvim_create_augroup("highlight_yank", { clear = true }),
  callback = function()
    vim.highlight.on_yank({ higroup = "IncSearch", timeout = 200 })
  end,
})

-- Remove trailing whitespace on save
vim.api.nvim_create_autocmd("BufWritePre", {
  group = vim.api.nvim_create_augroup("trim_whitespace", { clear = true }),
  pattern = "*",
  callback = function()
    local save = vim.fn.winsaveview()
    vim.cmd([[%s/\s\+$//e]])
    vim.fn.winrestview(save)
  end,
})

-- Restore cursor position
vim.api.nvim_create_autocmd("BufReadPost", {
  group = vim.api.nvim_create_augroup("restore_cursor", { clear = true }),
  callback = function()
    local mark = vim.api.nvim_buf_get_mark(0, '"')
    local lcount = vim.api.nvim_buf_line_count(0)
    if mark[1] > 0 and mark[1] <= lcount then
      pcall(vim.api.nvim_win_set_cursor, 0, mark)
    end
  end,
})

-- Auto-resize splits on window resize
vim.api.nvim_create_autocmd("VimResized", {
  group = vim.api.nvim_create_augroup("resize_splits", { clear = true }),
  callback = function()
    vim.cmd("wincmd =")
  end,
})

-- Set filetypes
vim.filetype.add({
  extension = {
    conf = "conf",
    env = "sh",
  },
  filename = {
    [".env"] = "sh",
  },
  pattern = {
    ["%.env%.[%w_.-]+"] = "sh",
  },
})
