-- Global Scripts Configuration
-- Generated automatically - do not edit manually
-- Generated at: 2026-03-23 15:40:42
-- Configuration source: /Users/solo/code/github/global_scripts

-- ============================================
-- Lua LSP 配置模块
-- ============================================

local M = {}

function M.setup(on_attach, capabilities)
  local lspconfig = require("lspconfig")

  lspconfig.lua_ls.setup({
    on_attach = on_attach,
    capabilities = capabilities,
    settings = {
      Lua = {
        runtime = {
          version = "LuaJIT",
        },
        diagnostics = {
          globals = { "vim", "use", "describe", "it", "before_each", "after_each" },
        },
        workspace = {
          library = {
            [vim.fn.expand("$VIMRUNTIME/lua")] = true,
            [vim.fn.stdpath("config") .. "/lua"] = true,
          },
          checkThirdParty = false,
        },
        telemetry = {
          enable = false,
        },
        format = {
          enable = true,
          defaultConfig = {
            indent_style = "space",
            indent_size = "2",
          },
        },
      },
    },
  })
end

return M
