-- Global Scripts Configuration
-- Generated automatically - do not edit manually
-- Generated at: 2026-03-23 15:40:42
-- Configuration source: /Users/solo/code/github/global_scripts

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
opt.winminwidth = 20             -- Prevent ultra-narrow side windows
opt.conceallevel = 2             -- Enable conceal for markdown rendering
opt.concealcursor = "nc"        -- Show raw markers only while editing in insert mode

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
-- IDE UI Zoom (Editor + Sidebar)
-- ============================================
local default_gui_font = "JetBrainsMono Nerd Font:h17"
if vim.o.guifont == nil or vim.o.guifont == "" then
  vim.o.guifont = default_gui_font
end

local function is_gui_client()
  return vim.g.neovide or vim.g.GuiLoaded or vim.fn.has("gui_running") == 1
end

local function parse_font_size(guifont)
  local size = guifont:match(":h(%d+)")
  if size then
    return tonumber(size)
  end
  return 17
end

local function set_font_size(new_size)
  if not is_gui_client() then
    vim.notify("Terminal Neovim detected (iTerm2): use iTerm2 font zoom (Cmd+= / Cmd+- / Cmd+0)", vim.log.levels.WARN)
    return
  end

  local safe_size = math.max(12, math.min(40, new_size))
  local current = vim.o.guifont
  if current == nil or current == "" then
    current = default_gui_font
  end

  local updated
  if current:match(":h%d+") then
    updated = current:gsub(":h%d+", ":h" .. safe_size)
  else
    updated = current .. ":h" .. safe_size
  end
  vim.o.guifont = updated

  if vim.g.neovide then
    vim.g.neovide_scale_factor = safe_size / 17
  end

  vim.notify("UI font size: " .. safe_size, vim.log.levels.INFO)
end

_G.gs_ui_zoom_in = function()
  set_font_size(parse_font_size(vim.o.guifont) + 1)
end

_G.gs_ui_zoom_out = function()
  set_font_size(parse_font_size(vim.o.guifont) - 1)
end

_G.gs_ui_zoom_reset = function()
  set_font_size(17)
end

vim.api.nvim_create_user_command("UIZoomIn", function() _G.gs_ui_zoom_in() end, {})
vim.api.nvim_create_user_command("UIZoomOut", function() _G.gs_ui_zoom_out() end, {})
vim.api.nvim_create_user_command("UIZoomReset", function() _G.gs_ui_zoom_reset() end, {})

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

-- ============================================
-- Go 文件使用 Tab 缩进 (参考 tmp/nvim)
-- ============================================
vim.api.nvim_create_autocmd({ "FileType" }, {
  pattern = { "go" },
  callback = function()
    vim.opt_local.expandtab = false -- 使用 tab 字符
    vim.opt_local.tabstop = 8
    vim.opt_local.softtabstop = 8
    vim.opt_local.shiftwidth = 8
  end,
})

-- ============================================
-- 退出时恢复光标样式 (参考 tmp/nvim)
-- ============================================
vim.api.nvim_create_autocmd({ "ExitPre" }, {
  callback = function()
    vim.opt.guicursor = "a:ver25-blinkon250-blinkoff400-blinkwait700"
  end,
})

-- ============================================
-- TrimWhitespace 命令 (参考 tmp/nvim)
-- ============================================
vim.api.nvim_create_user_command("TrimWhitespace", function()
  local view = vim.fn.winsaveview()
  vim.cmd([[%s/\s\+$//e]])
  vim.fn.winrestview(view)
end, {})

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
