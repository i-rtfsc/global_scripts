-- Global Scripts Configuration
-- Generated automatically - do not edit manually
-- Generated at: 2026-03-23 15:40:42
-- Configuration source: /Users/solo/code/github/global_scripts

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

        -- Lualine 集成配置
        lualine = {
          transparent = false,       -- lualine 中心栏透明度
        },

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
  -- Markdown Render - Markdown 实时渲染
  -- 在 Neovim 缓冲区内渲染标题/列表/代码块，更接近 IDE 阅读体验
  -- ==========================================
  {
    "MeanderingProgrammer/render-markdown.nvim",
    ft = { "markdown" },
    dependencies = {
      "nvim-treesitter/nvim-treesitter",
      "nvim-tree/nvim-web-devicons",
    },
    config = function()
      require("render-markdown").setup({
        file_types = { "markdown" },
        heading = {
          enabled = true,
          sign = false,
          icons = { "# ", "## ", "### ", "#### ", "##### ", "###### " },
        },
        code = {
          enabled = true,
          sign = false,
          width = "block",
          right_pad = 1,
        },
        bullet = {
          enabled = true,
          icons = { "•", "◦", "▪", "▸" },
        },
        checkbox = {
          enabled = true,
        },
        anti_conceal = {
          enabled = false,
        },
      })

      vim.keymap.set("n", "<leader>mr", function()
        local ok, cmd = pcall(vim.cmd, "RenderMarkdown toggle")
        if not ok then
          vim.notify("RenderMarkdown is not available in current buffer", vim.log.levels.WARN)
        end
      end, { desc = "Toggle Markdown render" })
    end,
  },

  -- ==========================================
  -- Mason - LSP 包管理器
  -- ==========================================
  {
    "williamboman/mason.nvim",
    lazy = false,
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

      vim.api.nvim_create_user_command("GSMason", function()
        vim.cmd("Mason")
      end, { desc = "Open Mason package manager" })

      vim.keymap.set("n", "<leader>pm", "<cmd>Mason<CR>", { desc = "Open Mason" })
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
          "ruff",
          "ts_ls",
          "eslint",
          "rust_analyzer",
          "gopls",
          "clangd",
          -- 注意：jdtls 不在这里，因为它需要特殊配置（使用 nvim-jdtls）
          -- 注意：Kotlin 使用 kotlin-lsp（手动通过 :MasonInstall kotlin-lsp 安装）
          -- jdtls 服务器需要通过 Mason 手动安装，但不要让 mason-lspconfig 自动配置
          "html",
          "cssls",
          "tailwindcss",
          "jsonls",
          "yamlls",
          "taplo",
          "marksman",
          "lemminx",
          "graphql",
          "astro",
          "svelte",
          "emmet_ls",
          "terraformls",
          "ansiblels",
          "vimls",
          "sqlls",
          "intelephense",
          "solargraph",
          "bashls",
          "dockerls",
          "docker_compose_language_service",
          "cmake",
        },
        automatic_installation = true,
        -- 所有语言都在下方手动 setup，关闭自动 enable 避免同一 server 重复起两份。
        automatic_enable = false,
      })
    end,
  },

  -- ==========================================
  -- LSP Configuration
  -- 语言服务器支持：Python, JS/TS, Rust, Go, C/C++, Java 等
  -- ==========================================
  {
    "neovim/nvim-lspconfig",
    event = { "BufReadPre", "BufNewFile" },
    dependencies = {
      "williamboman/mason-lspconfig.nvim",
      "hrsh7th/cmp-nvim-lsp",
      { "antosha417/nvim-lsp-file-operations", config = true },
      -- Java LSP 需要 nvim-jdtls 插件
      { "mfussenegger/nvim-jdtls" },
    },
    config = function()
      -- 完全禁用弃用警告
      vim.deprecate = function() end

      -- 兼容 Neovim 0.11+ 要求 position_encoding 参数
      local util = vim.lsp.util
      if util and not util.__gs_position_encoding_patched then
        util.__gs_position_encoding_patched = true
        local orig = util.make_position_params
        util.make_position_params = function(win, encoding)
          return orig(win, encoding or "utf-16")
        end
      end

      local lspconfig = require("lspconfig")
      local cmp_nvim_lsp = require("cmp_nvim_lsp")

      local function goto_definition_at_mouse()
        local m = vim.fn.getmousepos()
        if m and m.winid and m.winid ~= 0 then
          pcall(vim.api.nvim_set_current_win, m.winid)
          if m.line and m.line > 0 and m.column and m.column > 0 then
            pcall(vim.api.nvim_win_set_cursor, 0, { m.line, m.column - 1 })
          end
        end
        vim.lsp.buf.definition()
      end

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
        opts.desc = "Go to definition (JetBrains style)"
        vim.keymap.set("n", "<C-b>", "<cmd>Telescope lsp_definitions<CR>", opts)
        opts.desc = "Go to definition (Cmd+B)"
        vim.keymap.set("n", "<D-b>", "<cmd>Telescope lsp_definitions<CR>", opts)
        opts.desc = "Go to declaration (Cmd+Shift+B)"
        vim.keymap.set("n", "<D-S-b>", vim.lsp.buf.declaration, opts)
        opts.desc = "Go to definition with Cmd+Click"
        vim.keymap.set("n", "<D-LeftMouse>", goto_definition_at_mouse, opts)
        opts.desc = "Go to definition with Option+Click"
        vim.keymap.set("n", "<A-LeftMouse>", goto_definition_at_mouse, opts)
        opts.desc = "Go to definition with Shift+Click"
        vim.keymap.set("n", "<S-LeftMouse>", goto_definition_at_mouse, opts)
        opts.desc = "Go to definition with Ctrl+Click"
        vim.keymap.set("n", "<C-LeftMouse>", goto_definition_at_mouse, opts)

        opts.desc = "Show LSP implementations"
        vim.keymap.set("n", "gi", "<cmd>Telescope lsp_implementations<CR>", opts)
        opts.desc = "Go to implementation (Cmd+Alt+B)"
        vim.keymap.set("n", "<D-A-b>", "<cmd>Telescope lsp_implementations<CR>", opts)

        opts.desc = "Show LSP type definitions"
        vim.keymap.set("n", "gt", "<cmd>Telescope lsp_type_definitions<CR>", opts)
        opts.desc = "Go to type declaration (Cmd+Shift+B fallback)"
        vim.keymap.set("n", "<D-t>", "<cmd>Telescope lsp_type_definitions<CR>", opts)

        -- 代码操作
        opts.desc = "See available code actions"
        vim.keymap.set({ "n", "v" }, "<leader>ca", vim.lsp.buf.code_action, opts)
        opts.desc = "Code action (JetBrains style)"
        vim.keymap.set("n", "<A-CR>", vim.lsp.buf.code_action, opts)

        opts.desc = "Smart rename"
        vim.keymap.set("n", "<leader>rn", vim.lsp.buf.rename, opts)
        opts.desc = "Rename symbol (JetBrains style)"
        vim.keymap.set("n", "<S-F6>", vim.lsp.buf.rename, opts)

        -- 诊断
        opts.desc = "Show buffer diagnostics"
        vim.keymap.set("n", "<leader>D", "<cmd>Telescope diagnostics bufnr=0<CR>", opts)

        opts.desc = "Show line diagnostics"
        vim.keymap.set("n", "<leader>d", vim.diagnostic.open_float, opts)

        opts.desc = "Go to previous diagnostic"
        vim.keymap.set("n", "[d", vim.diagnostic.goto_prev, opts)
        opts.desc = "Previous issue (JetBrains style)"
        vim.keymap.set("n", "<S-F2>", vim.diagnostic.goto_prev, opts)

        opts.desc = "Go to next diagnostic"
        vim.keymap.set("n", "]d", vim.diagnostic.goto_next, opts)
        opts.desc = "Next issue (JetBrains style)"
        vim.keymap.set("n", "<F2>", vim.diagnostic.goto_next, opts)

        -- 文档
        opts.desc = "Show documentation for what is under cursor"
        vim.keymap.set("n", "K", vim.lsp.buf.hover, opts)
        opts.desc = "Quick definition preview (Cmd+Y / Ctrl+Shift+I style)"
        vim.keymap.set("n", "<D-y>", vim.lsp.buf.hover, opts)
        opts.desc = "Go to super / parent symbol (Cmd+U style)"
        vim.keymap.set("n", "<D-u>", vim.lsp.buf.type_definition, opts)

        opts.desc = "Find usages (JetBrains style)"
        vim.keymap.set("n", "<A-F7>", "<cmd>Telescope lsp_references<CR>", opts)

        opts.desc = "Reformat code (JetBrains style)"
        vim.keymap.set("n", "<C-A-l>", function()
          vim.lsp.buf.format({ async = true })
        end, opts)

        opts.desc = "Restart LSP"
        vim.keymap.set("n", "<leader>rs", ":LspRestart<CR>", opts)
      end

      -- 自动补全能力
      local capabilities = cmp_nvim_lsp.default_capabilities()

      -- 通用 LSP 键位（确保 on_attach 缺失时也可用）
      local lsp_keymaps_group = vim.api.nvim_create_augroup("GS_LspKeymaps", { clear = true })
      vim.api.nvim_create_autocmd("LspAttach", {
        group = lsp_keymaps_group,
        callback = function(ev)
          local bufnr = ev.buf
          local ok, tbuiltin = pcall(require, "telescope.builtin")
          local map = function(mode, lhs, rhs, desc)
            vim.keymap.set(mode, lhs, rhs, { buffer = bufnr, silent = true, desc = desc })
          end

          map("n", "gD", vim.lsp.buf.declaration, "Go to declaration")
          map("n", "gd", ok and tbuiltin.lsp_definitions or vim.lsp.buf.definition, "Go to definition")
          map("n", "<C-b>", ok and tbuiltin.lsp_definitions or vim.lsp.buf.definition, "Go to definition (JetBrains style)")
          map("n", "<D-b>", ok and tbuiltin.lsp_definitions or vim.lsp.buf.definition, "Go to definition (Cmd+B)")
          map("n", "<D-S-b>", vim.lsp.buf.declaration, "Go to declaration (Cmd+Shift+B)")
          map("n", "<D-LeftMouse>", goto_definition_at_mouse, "Go to definition with Cmd+Click")
          map("n", "<A-LeftMouse>", goto_definition_at_mouse, "Go to definition with Option+Click")
          map("n", "<S-LeftMouse>", goto_definition_at_mouse, "Go to definition with Shift+Click")
          map("n", "<C-LeftMouse>", goto_definition_at_mouse, "Go to definition with Ctrl+Click")
          map("n", "gi", ok and tbuiltin.lsp_implementations or vim.lsp.buf.implementation, "Go to implementation")
          map("n", "<D-A-b>", ok and tbuiltin.lsp_implementations or vim.lsp.buf.implementation, "Go to implementation (Cmd+Alt+B)")
          map("n", "gt", ok and tbuiltin.lsp_type_definitions or vim.lsp.buf.type_definition, "Type definition")
          map("n", "<D-t>", ok and tbuiltin.lsp_type_definitions or vim.lsp.buf.type_definition, "Type declaration (Cmd+T)")
          map("n", "gR", ok and tbuiltin.lsp_references or vim.lsp.buf.references, "References")
          map("n", "<A-F7>", ok and tbuiltin.lsp_references or vim.lsp.buf.references, "Find usages (JetBrains style)")

          map({ "n", "v" }, "<leader>ca", vim.lsp.buf.code_action, "Code action")
          map("n", "<A-CR>", vim.lsp.buf.code_action, "Code action (JetBrains style)")
          map("n", "<leader>rn", vim.lsp.buf.rename, "Rename symbol")
          map("n", "<S-F6>", vim.lsp.buf.rename, "Rename symbol (JetBrains style)")

          map("n", "[d", vim.diagnostic.goto_prev, "Prev diagnostic")
          map("n", "]d", vim.diagnostic.goto_next, "Next diagnostic")
          map("n", "<S-F2>", vim.diagnostic.goto_prev, "Previous issue (JetBrains style)")
          map("n", "<F2>", vim.diagnostic.goto_next, "Next issue (JetBrains style)")
          map("n", "<leader>d", vim.diagnostic.open_float, "Line diagnostics")
          map("n", "<leader>D", ok and function() tbuiltin.diagnostics({ bufnr = 0 }) end or vim.diagnostic.setloclist, "Buffer diagnostics")

          map("n", "K", vim.lsp.buf.hover, "Hover docs")
          map("n", "<D-y>", vim.lsp.buf.hover, "Quick definition preview (Cmd+Y)")
          map("n", "<D-u>", vim.lsp.buf.type_definition, "Go to parent/type symbol (Cmd+U)")
          map("n", "<F4>", ok and tbuiltin.lsp_definitions or vim.lsp.buf.definition, "Edit source (F4)")
          map("n", "<C-A-l>", function() vim.lsp.buf.format({ async = true }) end, "Reformat code (JetBrains style)")
          map("n", "<leader>rs", function() vim.cmd("LspRestart") end, "Restart LSP")
        end,
      })

      local recycle_group = vim.api.nvim_create_augroup("GS_LspRecycle", { clear = true })
      vim.api.nvim_create_autocmd({ "BufDelete", "BufWipeout" }, {
        group = recycle_group,
        callback = function()
          vim.defer_fn(function()
            for _, client in ipairs(vim.lsp.get_active_clients()) do
              local has_loaded_buffer = false
              for _, buf in ipairs(vim.lsp.get_buffers_by_client_id(client.id)) do
                if vim.api.nvim_buf_is_valid(buf) and vim.api.nvim_buf_is_loaded(buf) then
                  has_loaded_buffer = true
                  break
                end
              end
              if not has_loaded_buffer then
                vim.lsp.stop_client(client.id, true)
              end
            end
          end, 120)
        end,
      })

      -- 修复 position_encoding 警告（支持 UTF-16）
      capabilities.offsetEncoding = { "utf-16" }

      -- 诊断符号
      local signs = { Error = " ", Warn = " ", Hint = "󰠠 ", Info = " " }
      for type, icon in pairs(signs) do
        local hl = "DiagnosticSign" .. type
        vim.fn.sign_define(hl, { text = icon, texthl = hl, numhl = "" })
      end

      -- 配置所有 LSP 服务器
      -- 使用模块化配置（每个语言的配置在独立文件中）

      -- Lua
      require("lsp.lua").setup(on_attach, capabilities)

      -- Python
      require("lsp.python").setup(on_attach, capabilities)

      -- JavaScript/TypeScript (包括 ESLint)
      require("lsp.typescript").setup(on_attach, capabilities)

      -- Rust
      require("lsp.rust").setup(on_attach, capabilities)

      -- Go
      require("lsp.go").setup(on_attach, capabilities)

      -- C/C++
      require("lsp.clang").setup(on_attach, capabilities)

      -- Java (jdtls 比较特殊，使用 autocmd + FileType 延迟加载)
      require("lsp.java").setup(on_attach, capabilities)

      -- 简单 LSP 服务器（使用默认配置）
      local default_config = {
        capabilities = capabilities,
        on_attach = on_attach,
        flags = {
          debounce_text_changes = 150,
        },
      }

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

      -- CMake
      lspconfig.cmake.setup(default_config)

      -- Docs / Config / Infra
      if lspconfig.marksman then
        lspconfig.marksman.setup(default_config)
      end
      if lspconfig.taplo then
        lspconfig.taplo.setup(default_config)
      end
      if lspconfig.lemminx then
        lspconfig.lemminx.setup(default_config)
      end
      if lspconfig.terraformls then
        lspconfig.terraformls.setup(default_config)
      end
      if lspconfig.ansiblels then
        lspconfig.ansiblels.setup(default_config)
      end
      if lspconfig.vimls then
        lspconfig.vimls.setup(default_config)
      end
      if lspconfig.sqlls then
        lspconfig.sqlls.setup(default_config)
      end

      -- Frontend
      if lspconfig.graphql then
        lspconfig.graphql.setup(default_config)
      end
      if lspconfig.astro then
        lspconfig.astro.setup(default_config)
      end
      if lspconfig.svelte then
        lspconfig.svelte.setup(default_config)
      end
      if lspconfig.emmet_ls then
        lspconfig.emmet_ls.setup(vim.tbl_deep_extend("force", default_config, {
          filetypes = {
            "html", "css", "scss", "sass", "javascriptreact", "typescriptreact", "svelte", "vue",
          },
        }))
      end

      -- Backend
      if lspconfig.intelephense then
        lspconfig.intelephense.setup(default_config)
      end
      if lspconfig.solargraph then
        lspconfig.solargraph.setup(default_config)
      end
      if lspconfig.ruff then
        lspconfig.ruff.setup(default_config)
      end

      if lspconfig.docker_compose_language_service then
        lspconfig.docker_compose_language_service.setup(default_config)
      end

      -- Kotlin
      require("lsp.kotlin").setup(on_attach, capabilities)
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
          width = 42,
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
          theme = "auto",  -- 自动检测当前 colorscheme
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
  -- OSC52 Clipboard - 远程/终端复制桥接
  -- ==========================================
  {
    "ojroques/nvim-osc52",
    event = "VeryLazy",
    config = function()
      local ok, osc52 = pcall(require, "osc52")
      if not ok then
        return
      end

      osc52.setup({
        max_length = 0,
        silent = true,
        trim = false,
      })

      local copy = function()
        if vim.v.event.operator == "y" and vim.v.event.regname == "+" then
          osc52.copy_register("+")
        end
      end

      vim.api.nvim_create_autocmd("TextYankPost", {
        callback = copy,
      })
    end,
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
  performance = {
    rtp = {
      disabled_plugins = {
        "gzip",
        "zip",
        "zipPlugin",
        "tar",
        "tarPlugin",
        "tohtml",
        "tutor",
      },
    },
  },
})
