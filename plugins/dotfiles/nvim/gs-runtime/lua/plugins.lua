-- ============================================
-- Neovim Plugin Management with lazy.nvim
-- Global Scripts - 全栈开发配置
-- ============================================

-- Install lazy.nvim if not already installed
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not vim.loop.fs_stat(lazypath) then
  vim.fn.system({
    "git",
    "clone",
    "--filter=blob:none",
    "https://github.com/folke/lazy.nvim.git",
    "--branch=stable",
    lazypath,
  })
end
vim.opt.rtp:prepend(lazypath)

-- ============================================
-- Plugin Specifications
-- ============================================

local plugins = {
  -- ==========================================
  -- Color Scheme - 主题配色
  -- ==========================================

  -- 💡 切换主题方法：
  -- 1. 取消注释你想用的主题配置
  -- 2. 注释掉当前激活的主题
  -- 3. 重启 Neovim
  -- 或者在 Neovim 中按 <leader>ft 搜索主题实时切换

  -- One Dark 主题（Atom 官方移植版）⭐⭐⭐⭐⭐ 当前默认
  -- 最接近 Atom/VSCode/IDEA 的 One Dark 配色
  -- {
  --   "joshdick/onedark.vim",
  --   lazy = false,
  --   priority = 1000,
  --   config = function()
  --     -- 启用 24-bit 真彩色（推荐）
  --     vim.cmd([[
  --       if (has("termguicolors"))
  --         set termguicolors
  --       endif
  --     ]])

  --     -- 可选配置
  --     -- vim.g.onedark_terminal_italics = 1        -- 启用斜体注释
  --     -- vim.g.onedark_hide_endofbuffer = 1        -- 隐藏缓冲区结束符号 ~

  --     vim.cmd([[colorscheme onedark]])
  --   end,
  -- },

  -- Tokyo Night 主题（备选）
  -- 取消注释下面的配置并注释掉上面的 One Dark 即可使用
  -- {
  --   "folke/tokyonight.nvim",
  --   lazy = false,
  --   priority = 1000,
  --   config = function()
  --     require("tokyonight").setup({
  --       style = "night",
  --       transparent = false,
  --       terminal_colors = true,
  --       styles = {
  --         comments = { italic = true },
  --         keywords = { italic = true },
  --         functions = {},
  --         variables = {},
  --       },
  --     })
  --     vim.cmd([[colorscheme tokyonight]])
  --   end,
  -- },

  -- One Dark 主题（Lua 现代实现，可选）
  -- 如果上面的 joshdick/onedark.vim 有兼容问题，可以使用这个
  {
    "navarasu/onedark.nvim",
    lazy = false,
    priority = 1000,
    config = function()
      require("onedark").setup({
        style = "deep",              -- dark, darker, cool, deep, warm, warmer, light
        transparent = false,
        term_colors = true,
        ending_tildes = false,
        cmp_itemkind_reverse = false,
        code_style = {
          comments = "italic",
          keywords = "bold",
          functions = "none",
          strings = "none",
          variables = "none"
        },
        diagnostics = {
          darker = true,
          undercurl = true,
          background = true,
        },
      })
      require("onedark").load()
    end,
  },

  -- 其他主题选项
  -- { "catppuccin/nvim", name = "catppuccin", priority = 1000 },
  -- { "rebelot/kanagawa.nvim", priority = 1000 },
  -- { "EdenEast/nightfox.nvim", priority = 1000 },
  -- { "Mofiqul/dracula.nvim", priority = 1000 },

  -- ==========================================
  -- Treesitter - 语法高亮增强
  -- 支持：Rust, C/C++, Java, Kotlin, Go, Python, JS/TS 等
  -- ==========================================
  {
    "nvim-treesitter/nvim-treesitter",
    build = ":TSUpdate",
    event = { "BufReadPost", "BufNewFile" },
    dependencies = {
      "nvim-treesitter/nvim-treesitter-textobjects",
    },
    config = function()
      require("nvim-treesitter.configs").setup({
        ensure_installed = {
          -- Web 开发
          "html", "css", "javascript", "typescript", "tsx", "json", "yaml",
          -- 系统语言
          "c", "cpp", "rust", "go", "zig",
          -- JVM 语言
          "java", "kotlin", "scala",
          -- 脚本语言
          "python", "lua", "ruby", "php",
          -- Shell 和配置
          "bash", "fish", "vim", "vimdoc", "dockerfile",
          -- 文档
          "markdown", "markdown_inline",
          -- 其他
          "toml", "sql", "regex",
        },
        auto_install = true,
        highlight = {
          enable = true,
          additional_vim_regex_highlighting = false,
        },
        indent = { enable = true },
        incremental_selection = {
          enable = true,
          keymaps = {
            init_selection = "<C-space>",
            node_incremental = "<C-space>",
            scope_incremental = false,
            node_decremental = "<bs>",
          },
        },
        textobjects = {
          select = {
            enable = true,
            lookahead = true,
            keymaps = {
              ["af"] = "@function.outer",
              ["if"] = "@function.inner",
              ["ac"] = "@class.outer",
              ["ic"] = "@class.inner",
            },
          },
          move = {
            enable = true,
            set_jumps = true,
            goto_next_start = {
              ["]m"] = "@function.outer",
              ["]]"] = "@class.outer",
            },
            goto_next_end = {
              ["]M"] = "@function.outer",
              ["]["] = "@class.outer",
            },
            goto_previous_start = {
              ["[m"] = "@function.outer",
              ["[["] = "@class.outer",
            },
            goto_previous_end = {
              ["[M"] = "@function.outer",
              ["[]"] = "@class.outer",
            },
          },
        },
      })
    end,
  },

  -- ==========================================
  -- Mason - LSP 包管理器
  -- ==========================================
  {
    "williamboman/mason.nvim",
    config = function()
      require("mason").setup({
        ui = {
          icons = {
            package_installed = "✓",
            package_pending = "➜",
            package_uninstalled = "✗",
          },
        },
      })
    end,
  },

  -- ==========================================
  -- Mason LSP Config
  -- ==========================================
  {
    "williamboman/mason-lspconfig.nvim",
    dependencies = { "williamboman/mason.nvim" },
    config = function()
      require("mason-lspconfig").setup({
        ensure_installed = {
          "lua_ls",
          "pyright",
          "ts_ls",
          "eslint",
          "rust_analyzer",
          "gopls",
          "clangd",
          "jdtls",
          "html",
          "cssls",
          "tailwindcss",
          "jsonls",
          "yamlls",
          "bashls",
          "dockerls",
        },
        automatic_installation = true,
      })
    end,
  },

  -- ==========================================
  -- LSP Configuration
  -- 语言服务器支持：Python, JS/TS, Rust, Go, C/C++, Java 等
  -- ==========================================
  {
    "neovim/nvim-lspconfig",
    dependencies = {
      "williamboman/mason-lspconfig.nvim",
      "hrsh7th/cmp-nvim-lsp",
      { "antosha417/nvim-lsp-file-operations", config = true },
    },
    config = function()
      -- 完全禁用弃用警告
      vim.deprecate = function() end

      local lspconfig = require("lspconfig")
      local cmp_nvim_lsp = require("cmp_nvim_lsp")

      -- LSP 键位映射（当 LSP 附加到 buffer 时）
      local on_attach = function(client, bufnr)
        local opts = { buffer = bufnr, silent = true }

        -- 代码导航
        opts.desc = "Show LSP references"
        vim.keymap.set("n", "gR", "<cmd>Telescope lsp_references<CR>", opts)

        opts.desc = "Go to declaration"
        vim.keymap.set("n", "gD", vim.lsp.buf.declaration, opts)

        opts.desc = "Show LSP definitions"
        vim.keymap.set("n", "gd", "<cmd>Telescope lsp_definitions<CR>", opts)

        opts.desc = "Show LSP implementations"
        vim.keymap.set("n", "gi", "<cmd>Telescope lsp_implementations<CR>", opts)

        opts.desc = "Show LSP type definitions"
        vim.keymap.set("n", "gt", "<cmd>Telescope lsp_type_definitions<CR>", opts)

        -- 代码操作
        opts.desc = "See available code actions"
        vim.keymap.set({ "n", "v" }, "<leader>ca", vim.lsp.buf.code_action, opts)

        opts.desc = "Smart rename"
        vim.keymap.set("n", "<leader>rn", vim.lsp.buf.rename, opts)

        -- 诊断
        opts.desc = "Show buffer diagnostics"
        vim.keymap.set("n", "<leader>D", "<cmd>Telescope diagnostics bufnr=0<CR>", opts)

        opts.desc = "Show line diagnostics"
        vim.keymap.set("n", "<leader>d", vim.diagnostic.open_float, opts)

        opts.desc = "Go to previous diagnostic"
        vim.keymap.set("n", "[d", vim.diagnostic.goto_prev, opts)

        opts.desc = "Go to next diagnostic"
        vim.keymap.set("n", "]d", vim.diagnostic.goto_next, opts)

        -- 文档
        opts.desc = "Show documentation for what is under cursor"
        vim.keymap.set("n", "K", vim.lsp.buf.hover, opts)

        opts.desc = "Restart LSP"
        vim.keymap.set("n", "<leader>rs", ":LspRestart<CR>", opts)
      end

      -- 自动补全能力
      local capabilities = cmp_nvim_lsp.default_capabilities()

      -- 修复 position_encoding 警告（支持 UTF-16）
      capabilities.offsetEncoding = { "utf-16" }

      -- 诊断符号
      local signs = { Error = " ", Warn = " ", Hint = "󰠠 ", Info = " " }
      for type, icon in pairs(signs) do
        local hl = "DiagnosticSign" .. type
        vim.fn.sign_define(hl, { text = icon, texthl = hl, numhl = "" })
      end

      -- 配置所有 LSP 服务器
      local default_config = {
        capabilities = capabilities,
        on_attach = on_attach,
      }

      -- Lua
      lspconfig.lua_ls.setup(vim.tbl_extend("force", default_config, {
        settings = {
          Lua = {
            diagnostics = {
              globals = { "vim" },
            },
            workspace = {
              library = {
                [vim.fn.expand("$VIMRUNTIME/lua")] = true,
                [vim.fn.stdpath("config") .. "/lua"] = true,
              },
            },
          },
        },
      }))

      -- Python
      lspconfig.pyright.setup(default_config)

      -- JavaScript/TypeScript
      lspconfig.ts_ls.setup(default_config)
      lspconfig.eslint.setup(default_config)

      -- Rust
      lspconfig.rust_analyzer.setup(vim.tbl_extend("force", default_config, {
        settings = {
          ["rust-analyzer"] = {
            checkOnSave = {
              command = "clippy",
            },
          },
        },
      }))

      -- Go
      lspconfig.gopls.setup(default_config)

      -- C/C++
      lspconfig.clangd.setup(default_config)

      -- Java
      lspconfig.jdtls.setup(default_config)

      -- Web
      lspconfig.html.setup(default_config)
      lspconfig.cssls.setup(default_config)
      lspconfig.tailwindcss.setup(default_config)

      -- JSON/YAML
      lspconfig.jsonls.setup(default_config)
      lspconfig.yamlls.setup(default_config)

      -- Shell
      lspconfig.bashls.setup(default_config)

      -- Docker
      lspconfig.dockerls.setup(default_config)
    end,
  },

  -- ==========================================
  -- Auto-completion - 自动补全
  -- ==========================================
  {
    "hrsh7th/nvim-cmp",
    event = "InsertEnter",
    dependencies = {
      "hrsh7th/cmp-buffer",       -- Buffer completions
      "hrsh7th/cmp-path",         -- Path completions
      "hrsh7th/cmp-cmdline",      -- Command line completions
      "hrsh7th/cmp-nvim-lsp",     -- LSP completions
      "saadparwaiz1/cmp_luasnip", -- Snippet completions
      "L3MON4D3/LuaSnip",         -- Snippet engine
      "rafamadriz/friendly-snippets", -- Collection of snippets
    },
    config = function()
      local cmp = require("cmp")
      local luasnip = require("luasnip")

      -- Load snippets
      require("luasnip.loaders.from_vscode").lazy_load()

      cmp.setup({
        snippet = {
          expand = function(args)
            luasnip.lsp_expand(args.body)
          end,
        },
        mapping = cmp.mapping.preset.insert({
          ["<C-k>"] = cmp.mapping.select_prev_item(),
          ["<C-j>"] = cmp.mapping.select_next_item(),
          ["<C-b>"] = cmp.mapping.scroll_docs(-4),
          ["<C-f>"] = cmp.mapping.scroll_docs(4),
          ["<C-Space>"] = cmp.mapping.complete(),
          ["<C-e>"] = cmp.mapping.abort(),
          ["<CR>"] = cmp.mapping.confirm({ select = false }),
          ["<Tab>"] = cmp.mapping(function(fallback)
            if cmp.visible() then
              cmp.select_next_item()
            elseif luasnip.expand_or_jumpable() then
              luasnip.expand_or_jump()
            else
              fallback()
            end
          end, { "i", "s" }),
          ["<S-Tab>"] = cmp.mapping(function(fallback)
            if cmp.visible() then
              cmp.select_prev_item()
            elseif luasnip.jumpable(-1) then
              luasnip.jump(-1)
            else
              fallback()
            end
          end, { "i", "s" }),
        }),
        sources = {
          { name = "nvim_lsp" },
          { name = "luasnip" },
          { name = "buffer" },
          { name = "path" },
        },
        formatting = {
          format = function(entry, vim_item)
            vim_item.menu = ({
              nvim_lsp = "[LSP]",
              luasnip = "[Snippet]",
              buffer = "[Buffer]",
              path = "[Path]",
            })[entry.source.name]
            return vim_item
          end,
        },
        window = {
          completion = cmp.config.window.bordered(),
          documentation = cmp.config.window.bordered(),
        },
      })

      -- Command line completion
      cmp.setup.cmdline(":", {
        mapping = cmp.mapping.preset.cmdline(),
        sources = {
          { name = "path" },
          { name = "cmdline" },
        },
      })

      -- Search completion
      cmp.setup.cmdline("/", {
        mapping = cmp.mapping.preset.cmdline(),
        sources = {
          { name = "buffer" },
        },
      })
    end,
  },

  -- ==========================================
  -- Telescope - 模糊查找器
  -- ==========================================
  {
    "nvim-telescope/telescope.nvim",
    branch = "0.1.x",
    dependencies = {
      "nvim-lua/plenary.nvim",
      { "nvim-telescope/telescope-fzf-native.nvim", build = "make" },
      "nvim-tree/nvim-web-devicons",
    },
    config = function()
      local telescope = require("telescope")
      local actions = require("telescope.actions")

      telescope.setup({
        defaults = {
          path_display = { "truncate" },
          mappings = {
            i = {
              ["<C-k>"] = actions.move_selection_previous,
              ["<C-j>"] = actions.move_selection_next,
              ["<C-q>"] = actions.send_selected_to_qflist + actions.open_qflist,
            },
          },
        },
      })

      telescope.load_extension("fzf")

      -- Keymaps
      local keymap = vim.keymap.set
      keymap("n", "<leader>ff", "<cmd>Telescope find_files<cr>", { desc = "Find files" })
      keymap("n", "<leader>fr", "<cmd>Telescope oldfiles<cr>", { desc = "Recent files" })
      keymap("n", "<leader>fg", "<cmd>Telescope live_grep<cr>", { desc = "Live grep" })
      keymap("n", "<leader>fc", "<cmd>Telescope grep_string<cr>", { desc = "Find string under cursor" })
      keymap("n", "<leader>fb", "<cmd>Telescope buffers<cr>", { desc = "Find buffers" })
      keymap("n", "<leader>fh", "<cmd>Telescope help_tags<cr>", { desc = "Help tags" })
      keymap("n", "<leader>fm", "<cmd>Telescope marks<cr>", { desc = "Find marks" })
      keymap("n", "<leader>fk", "<cmd>Telescope keymaps<cr>", { desc = "Find keymaps" })
      keymap("n", "<leader>ft", "<cmd>Telescope colorscheme<cr>", { desc = "Color schemes" })
    end,
  },

  -- ==========================================
  -- File Explorer - 文件浏览器
  -- ==========================================
  {
    "nvim-tree/nvim-tree.lua",
    dependencies = { "nvim-tree/nvim-web-devicons" },
    config = function()
      require("nvim-tree").setup({
        view = {
          width = 35,
          relativenumber = true,
        },
        renderer = {
          indent_markers = {
            enable = true,
          },
          icons = {
            glyphs = {
              folder = {
                arrow_closed = "",
                arrow_open = "",
              },
            },
          },
        },
        actions = {
          open_file = {
            window_picker = {
              enable = false,
            },
          },
        },
        filters = {
          custom = { ".DS_Store" },
        },
        git = {
          ignore = false,
        },
      })

      -- Keymaps
      vim.keymap.set("n", "<leader>ee", "<cmd>NvimTreeToggle<CR>", { desc = "Toggle file explorer" })
      vim.keymap.set("n", "<leader>ef", "<cmd>NvimTreeFindFileToggle<CR>", { desc = "Toggle explorer on current file" })
      vim.keymap.set("n", "<leader>ec", "<cmd>NvimTreeCollapse<CR>", { desc = "Collapse file explorer" })
      vim.keymap.set("n", "<leader>er", "<cmd>NvimTreeRefresh<CR>", { desc = "Refresh file explorer" })

      -- 快速聚焦到文件浏览器（像 VSCode 一样）| Quick focus to file explorer (like VSCode)
      -- Ctrl+e: 聚焦到文件浏览器，如果未打开则打开 | Focus file explorer, open if closed
      vim.keymap.set("n", "<C-e>", "<cmd>NvimTreeFocus<CR>", { desc = "Focus file explorer" })
    end,
  },

  -- ==========================================
  -- Git Integration - Git 集成
  -- ==========================================
  {
    "lewis6991/gitsigns.nvim",
    event = { "BufReadPre", "BufNewFile" },
    config = function()
      require("gitsigns").setup({
        signs = {
          add = { text = "│" },
          change = { text = "│" },
          delete = { text = "_" },
          topdelete = { text = "‾" },
          changedelete = { text = "~" },
          untracked = { text = "┆" },
        },
        on_attach = function(bufnr)
          local gs = package.loaded.gitsigns

          local function map(mode, l, r, opts)
            opts = opts or {}
            opts.buffer = bufnr
            vim.keymap.set(mode, l, r, opts)
          end

          -- Navigation
          map("n", "]c", function()
            if vim.wo.diff then
              return "]c"
            end
            vim.schedule(function()
              gs.next_hunk()
            end)
            return "<Ignore>"
          end, { expr = true, desc = "Next git change" })

          map("n", "[c", function()
            if vim.wo.diff then
              return "[c"
            end
            vim.schedule(function()
              gs.prev_hunk()
            end)
            return "<Ignore>"
          end, { expr = true, desc = "Previous git change" })

          -- Actions
          map("n", "<leader>gs", gs.stage_hunk, { desc = "Stage hunk" })
          map("n", "<leader>gr", gs.reset_hunk, { desc = "Reset hunk" })
          map("v", "<leader>gs", function()
            gs.stage_hunk({ vim.fn.line("."), vim.fn.line("v") })
          end, { desc = "Stage hunk" })
          map("v", "<leader>gr", function()
            gs.reset_hunk({ vim.fn.line("."), vim.fn.line("v") })
          end, { desc = "Reset hunk" })
          map("n", "<leader>gS", gs.stage_buffer, { desc = "Stage buffer" })
          map("n", "<leader>gu", gs.undo_stage_hunk, { desc = "Undo stage hunk" })
          map("n", "<leader>gR", gs.reset_buffer, { desc = "Reset buffer" })
          map("n", "<leader>gp", gs.preview_hunk, { desc = "Preview hunk" })
          map("n", "<leader>gb", function()
            gs.blame_line({ full = true })
          end, { desc = "Blame line" })
          map("n", "<leader>gd", gs.diffthis, { desc = "Diff this" })
          map("n", "<leader>gD", function()
            gs.diffthis("~")
          end, { desc = "Diff this ~" })
        end,
      })
    end,
  },

  -- ==========================================
  -- Status Line - 状态栏美化
  -- ==========================================
  {
    "nvim-lualine/lualine.nvim",
    dependencies = { "nvim-tree/nvim-web-devicons" },
    config = function()
      require("lualine").setup({
        options = {
          theme = "tokyonight",
          component_separators = { left = "|", right = "|" },
          section_separators = { left = "", right = "" },
        },
        sections = {
          lualine_a = { "mode" },
          lualine_b = { "branch", "diff", "diagnostics" },
          lualine_c = { { "filename", path = 1 } },
          lualine_x = { "encoding", "fileformat", "filetype" },
          lualine_y = { "progress" },
          lualine_z = { "location" },
        },
      })
    end,
  },

  -- ==========================================
  -- Buffer Line - 缓冲区标签
  -- ==========================================
  {
    "akinsho/bufferline.nvim",
    dependencies = { "nvim-tree/nvim-web-devicons" },
    version = "*",
    config = function()
      require("bufferline").setup({
        options = {
          mode = "buffers",
          numbers = "none",
          close_command = "bdelete! %d",
          right_mouse_command = "bdelete! %d",
          left_mouse_command = "buffer %d",
          middle_mouse_command = nil,
          indicator = {
            style = "icon",
            icon = "▎",
          },
          buffer_close_icon = "",
          modified_icon = "●",
          close_icon = "",
          left_trunc_marker = "",
          right_trunc_marker = "",
          diagnostics = "nvim_lsp",
          offsets = {
            {
              filetype = "NvimTree",
              text = "File Explorer",
              highlight = "Directory",
              text_align = "left",
            },
          },
          separator_style = "thin",
          always_show_bufferline = true,
        },
      })

      -- Buffer 切换快捷键 | Buffer Navigation Keymaps
      local keymap = vim.keymap.set

      -- Tab 切换（只在普通模式下，插入模式用于补全）
      -- Tab navigation (normal mode only, insert mode reserved for completion)
      keymap("n", "<Tab>", "<cmd>BufferLineCycleNext<cr>", { desc = "Next buffer" })
      keymap("n", "<S-Tab>", "<cmd>BufferLineCyclePrev<cr>", { desc = "Previous buffer" })

      -- 备用方案：Alt+h/l 切换（更可靠）| Alternative: Alt+h/l (more reliable)
      keymap("n", "<A-l>", "<cmd>BufferLineCycleNext<cr>", { desc = "Next buffer" })
      keymap("n", "<A-h>", "<cmd>BufferLineCyclePrev<cr>", { desc = "Previous buffer" })

      -- 数字快速跳转 | Jump to buffer by number
      for i = 1, 9 do
        keymap("n", "<leader>" .. i, "<cmd>BufferLineGoToBuffer " .. i .. "<cr>",
          { desc = "Go to buffer " .. i })
      end

      -- Buffer 管理 | Buffer management
      keymap("n", "<leader>bp", "<cmd>BufferLinePick<cr>", { desc = "Pick buffer" })
      keymap("n", "<leader>bc", "<cmd>BufferLinePickClose<cr>", { desc = "Pick and close buffer" })
      keymap("n", "<leader>bd", "<cmd>bdelete<cr>", { desc = "Delete current buffer" })
      keymap("n", "<leader>bo", "<cmd>BufferLineCloseOthers<cr>", { desc = "Close other buffers" })
      keymap("n", "<leader>br", "<cmd>BufferLineCloseRight<cr>", { desc = "Close buffers to the right" })
      keymap("n", "<leader>bl", "<cmd>BufferLineCloseLeft<cr>", { desc = "Close buffers to the left" })
    end,
  },

  -- ==========================================
  -- Auto Pairs - 自动补全括号
  -- ==========================================
  {
    "windwp/nvim-autopairs",
    event = "InsertEnter",
    config = function()
      require("nvim-autopairs").setup({
        check_ts = true,
        ts_config = {
          lua = { "string" },
          javascript = { "template_string" },
        },
      })

      local cmp_autopairs = require("nvim-autopairs.completion.cmp")
      local cmp = require("cmp")
      cmp.event:on("confirm_done", cmp_autopairs.on_confirm_done())
    end,
  },

  -- ==========================================
  -- Comment - 快速注释
  -- ==========================================
  {
    "numToStr/Comment.nvim",
    event = { "BufReadPre", "BufNewFile" },
    config = function()
      require("Comment").setup()
    end,
  },

  -- ==========================================
  -- Indent Guides - 缩进指示线
  -- ==========================================
  {
    "lukas-reineke/indent-blankline.nvim",
    main = "ibl",
    event = { "BufReadPre", "BufNewFile" },
    config = function()
      require("ibl").setup({
        indent = {
          char = "│",
        },
        scope = {
          enabled = true,
          show_start = true,
          show_end = false,
        },
      })
    end,
  },

  -- ==========================================
  -- Which Key - 快捷键提示
  -- ==========================================
  {
    "folke/which-key.nvim",
    event = "VeryLazy",
    init = function()
      vim.o.timeout = true
      vim.o.timeoutlen = 300
    end,
    config = function()
      require("which-key").setup()
    end,
  },

  -- ==========================================
  -- Surround - 快速包围
  -- ==========================================
  {
    "kylechui/nvim-surround",
    event = { "BufReadPre", "BufNewFile" },
    version = "*",
    config = function()
      require("nvim-surround").setup()
    end,
  },

  -- ==========================================
  -- Todo Comments - TODO 高亮
  -- ==========================================
  {
    "folke/todo-comments.nvim",
    event = { "BufReadPre", "BufNewFile" },
    dependencies = { "nvim-lua/plenary.nvim" },
    config = function()
      require("todo-comments").setup()

      vim.keymap.set("n", "<leader>fT", "<cmd>TodoTelescope<cr>", { desc = "Find todos" })
    end,
  },

  -- ==========================================
  -- Alpha - Dashboard 启动页
  -- ==========================================
  {
    "goolord/alpha-nvim",
    event = "VimEnter",
    dependencies = { "nvim-tree/nvim-web-devicons" },
    config = function()
      local alpha = require("alpha")
      local dashboard = require("alpha.themes.dashboard")

      dashboard.section.header.val = {
        "                                                     ",
        "  ███╗   ██╗███████╗ ██████╗ ██╗   ██╗██╗███╗   ███╗ ",
        "  ████╗  ██║██╔════╝██╔═══██╗██║   ██║██║████╗ ████║ ",
        "  ██╔██╗ ██║█████╗  ██║   ██║██║   ██║██║██╔████╔██║ ",
        "  ██║╚██╗██║██╔══╝  ██║   ██║╚██╗ ██╔╝██║██║╚██╔╝██║ ",
        "  ██║ ╚████║███████╗╚██████╔╝ ╚████╔╝ ██║██║ ╚═╝ ██║ ",
        "  ╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═══╝  ╚═╝╚═╝     ╚═╝ ",
        "                                                     ",
      }

      dashboard.section.buttons.val = {
        dashboard.button("f", "  Find file", ":Telescope find_files <CR>"),
        dashboard.button("e", "  New file", ":ene <BAR> startinsert <CR>"),
        dashboard.button("r", "  Recent files", ":Telescope oldfiles <CR>"),
        dashboard.button("g", "  Find text", ":Telescope live_grep <CR>"),
        dashboard.button("c", "  Config", ":e $MYVIMRC <CR>"),
        dashboard.button("q", "  Quit", ":qa<CR>"),
      }

      alpha.setup(dashboard.opts)

      vim.cmd([[autocmd FileType alpha setlocal nofoldenable]])
    end,
  },

  -- ==========================================
  -- Flash - 快速跳转导航
  -- ==========================================
  {
    "folke/flash.nvim",
    event = "VeryLazy",
    opts = {},
    keys = {
      {
        "s",
        mode = { "n", "x", "o" },
        function()
          require("flash").jump()
        end,
        desc = "Flash",
      },
      {
        "S",
        mode = { "n", "x", "o" },
        function()
          require("flash").treesitter()
        end,
        desc = "Flash Treesitter",
      },
      {
        "r",
        mode = "o",
        function()
          require("flash").remote()
        end,
        desc = "Remote Flash",
      },
      {
        "R",
        mode = { "o", "x" },
        function()
          require("flash").treesitter_search()
        end,
        desc = "Treesitter Search",
      },
    },
  },

  -- ==========================================
  -- Trouble - 更好的诊断列表
  -- ==========================================
  {
    "folke/trouble.nvim",
    dependencies = { "nvim-tree/nvim-web-devicons" },
    opts = {},
    cmd = "Trouble",
    keys = {
      {
        "<leader>xx",
        "<cmd>Trouble diagnostics toggle<cr>",
        desc = "Diagnostics (Trouble)",
      },
      {
        "<leader>xX",
        "<cmd>Trouble diagnostics toggle filter.buf=0<cr>",
        desc = "Buffer Diagnostics (Trouble)",
      },
      {
        "<leader>cs",
        "<cmd>Trouble symbols toggle focus=false<cr>",
        desc = "Symbols (Trouble)",
      },
      {
        "<leader>cl",
        "<cmd>Trouble lsp toggle focus=false win.position=right<cr>",
        desc = "LSP Definitions / references / ... (Trouble)",
      },
      {
        "<leader>xL",
        "<cmd>Trouble loclist toggle<cr>",
        desc = "Location List (Trouble)",
      },
      {
        "<leader>xQ",
        "<cmd>Trouble qflist toggle<cr>",
        desc = "Quickfix List (Trouble)",
      },
    },
  },

  -- ==========================================
  -- Noice - 增强的 UI
  -- ==========================================
  {
    "folke/noice.nvim",
    enabled = true,
    lazy = true,
    event = "VeryLazy",
    dependencies = {
      "MunifTanjim/nui.nvim",
      "rcarriga/nvim-notify",
    },
    config = function()
      -- 安全加载：检查依赖是否可用
      local has_noice = pcall(require, "noice")
      if not has_noice then
        return
      end

      require("noice").setup({
        lsp = {
          -- 覆盖 markdown 渲染，以便使用 Treesitter
          override = {
            ["vim.lsp.util.convert_input_to_markdown_lines"] = true,
            ["vim.lsp.util.stylize_markdown"] = true,
            ["cmp.entry.get_documentation"] = true,
          },
        },
        -- 可以在这里添加任何 noice 配置
        presets = {
          bottom_search = true,         -- 使用经典的底部命令行进行搜索
          command_palette = true,        -- 将命令行定位到屏幕中央
          long_message_to_split = true,  -- 长消息将发送到拆分
          inc_rename = false,            -- 为 inc-rename.nvim 启用输入对话框
          lsp_doc_border = false,        -- 为悬停文档和签名帮助添加边框
        },
      })
    end,
  },

  -- ==========================================
  -- Notify - 通知增强
  -- ==========================================
  {
    "rcarriga/nvim-notify",
    opts = {
      timeout = 3000,
      max_height = function()
        return math.floor(vim.o.lines * 0.75)
      end,
      max_width = function()
        return math.floor(vim.o.columns * 0.75)
      end,
    },
  },

  -- ==========================================
  -- Illuminate - 高亮相同单词
  -- ==========================================
  {
    "RRethy/vim-illuminate",
    event = { "BufReadPost", "BufNewFile" },
    opts = {
      delay = 200,
      large_file_cutoff = 2000,
      large_file_overrides = {
        providers = { "lsp" },
      },
    },
    config = function(_, opts)
      require("illuminate").configure(opts)
    end,
  },

  -- ==========================================
  -- Mini.nvim - 轻量级实用工具集合
  -- ==========================================
  {
    "echasnovski/mini.nvim",
    version = false,
    config = function()
      -- Mini.ai - 扩展文本对象
      require("mini.ai").setup()

      -- Mini.bufremove - 更好的缓冲区删除
      require("mini.bufremove").setup()

      -- Mini.pairs - 自动配对（如果不想用 nvim-autopairs 可以启用这个）
      -- require("mini.pairs").setup()
    end,
  },
}

-- ============================================
-- Setup lazy.nvim
-- ============================================

require("lazy").setup(plugins, {
  checker = {
    enabled = true,
    notify = false,
  },
  change_detection = {
    notify = false,
  },
})
