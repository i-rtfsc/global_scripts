-- ============================================
-- Neovim Key Mappings Configuration
-- ============================================

local keymap = vim.keymap.set
local opts = { noremap = true, silent = true }

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

-- ============================================
-- Insert Mode Mappings
-- ============================================

-- Navigation in insert mode
keymap("i", "<C-h>", "<Left>", opts)
keymap("i", "<C-j>", "<Down>", opts)
keymap("i", "<C-k>", "<Up>", opts)
keymap("i", "<C-l>", "<Right>", opts)

-- ============================================
-- Normal Mode Mappings
-- ============================================

-- Better page navigation
keymap("n", "<C-d>", "<C-d>zz", opts)
keymap("n", "<C-u>", "<C-u>zz", opts)

-- Keep search centered
keymap("n", "n", "nzzzv", opts)
keymap("n", "N", "Nzzzv", opts)

-- Join lines without moving cursor
keymap("n", "J", "mzJ`z", opts)

-- Select all
keymap("n", "<C-a>", "ggVG", { desc = "Select all" })

-- Increment/decrement
keymap("n", "+", "<C-a>", opts)
keymap("n", "-", "<C-x>", opts)

-- ============================================
-- File Explorer (Netrw)
-- ============================================
keymap("n", "<leader>e", ":Explore<CR>", { desc = "File explorer" })
keymap("n", "<leader>E", ":Lexplore<CR>", { desc = "File explorer (left)" })

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
keymap("n", "<leader>th", ":split | terminal<CR>", { desc = "Terminal horizontal split" })

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

-- ============================================
-- Command Mode Mappings
-- ============================================

-- Save with sudo
keymap("c", "w!!", "w !sudo tee % > /dev/null", opts)
