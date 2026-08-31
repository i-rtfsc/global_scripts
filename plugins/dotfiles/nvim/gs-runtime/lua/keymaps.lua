-- Global Scripts Configuration
-- Generated automatically - do not edit manually
-- Generated at: 2026-03-23 15:40:42
-- Configuration source: /Users/solo/code/github/global_scripts

-- ============================================
-- Neovim Key Mappings Configuration
-- ============================================

local keymap = vim.keymap.set
local opts = { noremap = true, silent = true }

local function duplicate_current_line()
  local line = vim.api.nvim_get_current_line()
  local row = vim.api.nvim_win_get_cursor(0)[1]
  vim.api.nvim_buf_set_lines(0, row, row, false, { line })
end

local function toggle_comment_current_line()
  local ok, api = pcall(require, "Comment.api")
  if ok then
    api.toggle.linewise.current()
  end
end

local function organize_imports()
  vim.lsp.buf.code_action({
    context = { only = { "source.organizeImports" }, diagnostics = {} },
    apply = true,
  })
end

-- ============================================
-- General Mappings
-- ============================================

-- Better escape
keymap("i", "jk", "<ESC>", opts)
keymap("i", "kj", "<ESC>", opts)

-- Save and quit
keymap("n", "<leader>w", ":w<CR>", { desc = "Save file" })
keymap("n", "<leader>q", ":q<CR>", { desc = "Quit" })
keymap("n", "<leader>Q", ":qa!<CR>", { desc = "Quit all without saving" })
keymap("n", "<leader>x", ":x<CR>", { desc = "Save and quit" })
keymap({ "n", "i", "v" }, "<C-s>", "<Esc><cmd>w<CR>", { desc = "Save file (IDE style)", silent = true })
keymap({ "n", "i", "v" }, "<D-s>", "<Esc><cmd>w<CR>", { desc = "Save file (JetBrains)" })

-- Clear search highlights
keymap("n", "<leader>h", ":nohlsearch<CR>", { desc = "Clear highlights" })
keymap("n", "<Esc>", "<cmd>nohlsearch<CR>", opts)

-- Better window navigation
keymap("n", "<C-h>", "<C-w>h", { desc = "Move to left window" })
keymap("n", "<C-j>", "<C-w>j", { desc = "Move to bottom window" })
keymap("n", "<C-k>", "<C-w>k", { desc = "Move to top window" })
keymap("n", "<C-l>", "<C-w>l", { desc = "Move to right window" })

-- Resize windows
keymap("n", "<C-Up>", ":resize +2<CR>", opts)
keymap("n", "<C-Down>", ":resize -2<CR>", opts)
keymap("n", "<C-Left>", ":vertical resize -2<CR>", opts)
keymap("n", "<C-Right>", ":vertical resize +2<CR>", opts)

-- 更大幅度调整窗口（Shift + 方向键）| Larger window resize (Shift + arrows)
keymap("n", "<S-Up>", ":resize +10<CR>", opts)
keymap("n", "<S-Down>", ":resize -10<CR>", opts)
keymap("n", "<S-Left>", ":vertical resize -10<CR>", opts)
keymap("n", "<S-Right>", ":vertical resize +10<CR>", opts)

-- Ctrl+Shift+hjkl 调整窗口 (参考 tmp/nvim)
keymap("n", "<C-S-j>", "<cmd>res +2<CR>", opts)
keymap("n", "<C-S-k>", "<cmd>res -2<CR>", opts)
keymap("n", "<C-S-h>", "<cmd>vertical resize -2<CR>", opts)
keymap("n", "<C-S-l>", "<cmd>vertical resize +2<CR>", opts)

-- 快速平均分配窗口大小 | Equalize window sizes quickly
keymap("n", "<leader>=", "<C-w>=", { desc = "Equalize window sizes" })
keymap("n", "<leader>|", ":vertical resize 80<CR>", { desc = "Set window width to 80" })
keymap("n", "<leader>_", ":resize 20<CR>", { desc = "Set window height to 20" })


-- Split windows
keymap("n", "<leader>sv", ":vsplit<CR>", { desc = "Split vertically" })
keymap("n", "<leader>sh", ":split<CR>", { desc = "Split horizontally" })
keymap("n", "<leader>sc", ":close<CR>", { desc = "Close split" })

-- Navigate buffers
keymap("n", "<S-l>", ":bnext<CR>", { desc = "Next buffer" })
keymap("n", "<S-h>", ":bprevious<CR>", { desc = "Previous buffer" })
keymap("n", "<leader>bd", ":bdelete<CR>", { desc = "Delete buffer" })

-- Navigate tabs
keymap("n", "<leader>tn", ":tabnew<CR>", { desc = "New tab" })
keymap("n", "<leader>tc", ":tabclose<CR>", { desc = "Close tab" })
keymap("n", "<leader>to", ":tabonly<CR>", { desc = "Close other tabs" })
keymap("n", "<leader>tl", ":tabnext<CR>", { desc = "Next tab" })
keymap("n", "<leader>th", ":tabprevious<CR>", { desc = "Previous tab" })
keymap("n", "<D-w>", ":bdelete<CR>", { desc = "Close file (JetBrains)" })

-- ============================================
-- Visual Mode Mappings
-- ============================================

-- Stay in indent mode
keymap("v", "<", "<gv", opts)
keymap("v", ">", ">gv", opts)

-- Move text up and down
keymap("v", "J", ":m '>+1<CR>gv=gv", opts)
keymap("v", "K", ":m '<-2<CR>gv=gv", opts)

-- Paste without yanking
keymap("v", "p", '"_dP', opts)

-- System clipboard friendly copy/paste
keymap({ "n", "v" }, "<leader>y", '"+y', { desc = "Copy to system clipboard" })
keymap("n", "<leader>Y", '"+Y', { desc = "Copy line to system clipboard" })
keymap({ "n", "v" }, "<leader>p", '"+p', { desc = "Paste from system clipboard" })
keymap({ "n", "v" }, "<leader>P", '"+P', { desc = "Paste before from system clipboard" })

-- ============================================
-- Insert Mode Mappings
-- ============================================

-- Navigation in insert mode (原有)
keymap("i", "<C-h>", "<Left>", opts)
keymap("i", "<C-j>", "<Down>", opts)
keymap("i", "<C-k>", "<Up>", opts)
-- keymap("i", "<C-l>", "<Right>", opts)  -- 被下面的覆盖

-- Emacs 风格行首/行尾 (参考 tmp/nvim)
keymap("i", "<C-a>", "<Home>", { noremap = true, silent = true, desc = "Move to line start" })
keymap("i", "<C-e>", "<End>", { noremap = true, silent = true, desc = "Move to line end" })
keymap("i", "<C-l>", "<Right>", { noremap = true, silent = true, desc = "Move right" })

-- ============================================
-- Normal Mode Mappings
-- ============================================

-- Better page navigation
keymap("n", "<C-d>", "<C-d>zz", opts)
keymap("n", "<C-u>", "<C-u>zz", opts)

-- Jump navigation (IDE style)
keymap("n", "<A-Left>", "<C-o>", { desc = "Back" })
keymap("n", "<A-Right>", "<C-i>", { desc = "Forward" })
keymap("n", "<leader>jb", "<C-o>", { desc = "Back (jump list)" })
keymap("n", "<leader>jf", "<C-i>", { desc = "Forward (jump list)" })

-- Keep search centered
keymap("n", "n", "nzzzv", opts)
keymap("n", "N", "Nzzzv", opts)

-- Join lines without moving cursor
keymap("n", "J", "mzJ`z", opts)

-- Select all
keymap("n", "<C-a>", "ggVG", { desc = "Select all" })
keymap("n", "<D-a>", "ggVG", { desc = "Select all (JetBrains)" })

-- Increment/decrement
keymap("n", "+", "<C-a>", opts)
keymap("n", "-", "<C-x>", opts)

-- ============================================
-- File Explorer (Netrw)
-- ============================================
keymap("n", "<leader>e", ":Explore<CR>", { desc = "File explorer" })
keymap("n", "<leader>E", ":Lexplore<CR>", { desc = "File explorer (left)" })
keymap("n", "<C-p>", "<cmd>Telescope find_files<CR>", { desc = "Search files (IDE style)" })
keymap("n", "<C-S-f>", "<cmd>Telescope live_grep<CR>", { desc = "Search in files (IDE style)" })
keymap("n", "<leader><leader>", "<cmd>Telescope find_files<CR>", { desc = "Search everywhere" })
keymap("n", "<D-p>", "<cmd>Telescope find_files<CR>", { desc = "Go to file (JetBrains)" })
keymap("n", "<D-e>", "<cmd>Telescope oldfiles<CR>", { desc = "Recent files (JetBrains)" })
keymap("n", "<D-S-o>", "<cmd>Telescope lsp_document_symbols<CR>", { desc = "File structure (JetBrains)" })
keymap("n", "<D-S-f>", "<cmd>Telescope live_grep<CR>", { desc = "Find in path (JetBrains)" })
keymap("n", "<D-S-a>", "<cmd>Telescope commands<CR>", { desc = "Find action (JetBrains)" })
keymap("n", "<D-o>", "<cmd>Telescope lsp_document_symbols<CR>", { desc = "Go to symbol (JetBrains)" })
keymap("n", "<D-S-n>", "<cmd>Telescope lsp_dynamic_workspace_symbols<CR>", { desc = "Go to symbol in project (JetBrains)" })
keymap("n", "<D-S-b>", "<cmd>NvimTreeFocus<CR>", { desc = "Toggle focus project tool window (JetBrains)" })
keymap("n", "<D-1>", "<cmd>NvimTreeFocus<CR>", { desc = "Focus project tool window (JetBrains)" })
keymap("n", "<D-4>", "<cmd>Trouble diagnostics toggle<CR>", { desc = "Focus problems tool window (JetBrains)" })

-- ============================================
-- Terminal Mappings
-- ============================================

-- Better terminal navigation
keymap("t", "<C-h>", "<C-\\><C-N><C-w>h", opts)
keymap("t", "<C-j>", "<C-\\><C-N><C-w>j", opts)
keymap("t", "<C-k>", "<C-\\><C-N><C-w>k", opts)
keymap("t", "<C-l>", "<C-\\><C-N><C-w>l", opts)
keymap("t", "<Esc>", "<C-\\><C-n>", opts)

-- Open terminal
keymap("n", "<leader>tt", ":terminal<CR>", { desc = "Open terminal" })
keymap("n", "<leader>tv", ":vsplit | terminal<CR>", { desc = "Terminal vertical split" })
-- keymap("n", "<leader>th", ":split | terminal<CR>", { desc = "Terminal horizontal split" })  -- 与 tab prev 冲突

-- ============================================
-- Quickfix and Location List
-- ============================================

keymap("n", "<leader>co", ":copen<CR>", { desc = "Open quickfix" })
keymap("n", "<leader>cc", ":cclose<CR>", { desc = "Close quickfix" })
keymap("n", "<leader>cn", ":cnext<CR>", { desc = "Next quickfix item" })
keymap("n", "<leader>cp", ":cprev<CR>", { desc = "Previous quickfix item" })

keymap("n", "<leader>lo", ":lopen<CR>", { desc = "Open location list" })
keymap("n", "<leader>lc", ":lclose<CR>", { desc = "Close location list" })
keymap("n", "<leader>ln", ":lnext<CR>", { desc = "Next location item" })
keymap("n", "<leader>lp", ":lprev<CR>", { desc = "Previous location item" })

-- ============================================
-- LSP Mappings (will be set up in LSP config)
-- ============================================
-- These will be configured when LSP attaches to a buffer
-- See plugins.lua for LSP-specific keymaps

-- ============================================
-- Telescope Mappings (will be configured in plugins.lua)
-- ============================================
-- <leader>ff - Find files
-- <leader>fg - Live grep
-- <leader>fb - Find buffers
-- <leader>fh - Help tags
-- etc.

-- ============================================
-- Diagnostic Mappings
-- ============================================

keymap("n", "<leader>dd", vim.diagnostic.open_float, { desc = "Open diagnostic float" })
keymap("n", "[d", vim.diagnostic.goto_prev, { desc = "Previous diagnostic" })
keymap("n", "]d", vim.diagnostic.goto_next, { desc = "Next diagnostic" })
keymap("n", "<leader>dl", vim.diagnostic.setloclist, { desc = "Diagnostic location list" })

-- ============================================
-- Utility Mappings
-- ============================================

-- Source current file
keymap("n", "<leader>so", ":source %<CR>", { desc = "Source current file" })

-- Toggle spell check
keymap("n", "<leader>s", ":set spell!<CR>", { desc = "Toggle spell check" })

-- Format document
keymap("n", "<leader>fm", vim.lsp.buf.format, { desc = "Format document" })
keymap("n", "<D-A-l>", function()
  vim.lsp.buf.format({ async = true })
end, { desc = "Reformat code (JetBrains)" })

keymap("n", "<D-A-o>", organize_imports, { desc = "Optimize imports (JetBrains)" })
keymap("n", "<leader>oi", organize_imports, { desc = "Organize imports" })

-- Comment toggle (IDE style)
keymap("n", "<C-_>", toggle_comment_current_line, { desc = "Toggle comment" })
keymap("v", "<C-_>", "<Esc><cmd>lua require('Comment.api').toggle.linewise(vim.fn.visualmode())<CR>",
  { desc = "Toggle comment selection" })
keymap("n", "<D-/>", toggle_comment_current_line, { desc = "Toggle comment (JetBrains)" })
keymap("n", "<D-_>", toggle_comment_current_line, { desc = "Toggle comment (JetBrains)" })

-- JetBrains-like editing shortcuts
keymap("n", "<A-Down>", ":m .+1<CR>==", { desc = "Move line down" })
keymap("n", "<A-Up>", ":m .-2<CR>==", { desc = "Move line up" })
keymap("i", "<A-Down>", "<Esc>:m .+1<CR>==gi", { desc = "Move line down" })
keymap("i", "<A-Up>", "<Esc>:m .-2<CR>==gi", { desc = "Move line up" })
keymap("n", "<D-d>", duplicate_current_line, { desc = "Duplicate line (JetBrains)" })
keymap("n", "<D-f>", "/", { desc = "Find in file (JetBrains)" })
keymap("n", "<D-r>", ":%s///g<Left><Left><Left>", { desc = "Replace in file (JetBrains)" })
keymap("n", "<D-g>", "n", { desc = "Find next (JetBrains)" })
keymap("n", "<D-S-g>", "N", { desc = "Find previous (JetBrains)" })
keymap("n", "<D-[>", "<C-o>", { desc = "Back (JetBrains)" })
keymap("n", "<D-]>", "<C-i>", { desc = "Forward (JetBrains)" })
keymap("n", "<D-n>", "<cmd>enew<CR>", { desc = "New file (JetBrains)" })

-- UI 字号缩放（GUI 客户端生效：Neovide/NvimQt 等）
keymap("n", "<D-=>", "<cmd>UIZoomIn<CR>", { desc = "Zoom in UI (JetBrains)" })
keymap("n", "<D-+>", "<cmd>UIZoomIn<CR>", { desc = "Zoom in UI (JetBrains)" })
keymap("n", "<D-->", "<cmd>UIZoomOut<CR>", { desc = "Zoom out UI (JetBrains)" })
keymap("n", "<D-0>", "<cmd>UIZoomReset<CR>", { desc = "Reset UI zoom (JetBrains)" })

-- Replace word under cursor
keymap("n", "<leader>r", [[:%s/\<<C-r><C-w>\>/<C-r><C-w>/gI<Left><Left><Left>]], { desc = "Replace word under cursor" })

-- Make file executable
keymap("n", "<leader>mx", ":!chmod +x %<CR>", { desc = "Make file executable", silent = true })

-- Copy file path
keymap("n", "<leader>yp", ":let @+ = expand('%:p')<CR>", { desc = "Copy file path" })
keymap("n", "<leader>yr", ":let @+ = expand('%')<CR>", { desc = "Copy relative path" })

-- Toggle line numbers
keymap("n", "<leader>ln", ":set number!<CR>", { desc = "Toggle line numbers" })
keymap("n", "<leader>lr", ":set relativenumber!<CR>", { desc = "Toggle relative numbers" })

-- Toggle wrap
keymap("n", "<leader>lw", ":set wrap!<CR>", { desc = "Toggle line wrap" })

-- Trim whitespace (参考 tmp/nvim)
keymap("n", "<leader>ct", "<cmd>TrimWhitespace<cr>", { desc = "Trim trailing whitespace" })

-- ============================================
-- Python fmt: skip 切换 (参考 tmp/nvim)
-- ============================================
_G.toggle_fmt_skip = function(start_line, end_line)
  local buf = 0
  for i = start_line, end_line do
    local line = vim.api.nvim_buf_get_lines(buf, i - 1, i, false)[1]
    if line:match("# fmt: skip%s*$") then
      -- 删除尾部 fmt: skip
      local new_line = line:gsub("%s*# fmt: skip%s*$", "")
      vim.api.nvim_buf_set_lines(buf, i - 1, i, false, { new_line })
    else
      -- 添加尾部 fmt: skip
      vim.api.nvim_buf_set_lines(buf, i - 1, i, false, { line .. " # fmt: skip" })
    end
  end
end

-- 普通模式 toggle 当前行 fmt: skip
keymap("n", "gcs", [[:lua _G.toggle_fmt_skip(vim.fn.line("."), vim.fn.line("."))<CR>]],
  { noremap = true, silent = true, desc = "Toggle # fmt: skip" })

-- ============================================
-- Command Mode Mappings
-- ============================================

-- Save with sudo
keymap("c", "w!!", "w !sudo tee % > /dev/null", opts)
