-- ============================================
-- Rust LSP 配置模块
-- ============================================

local M = {}

function M.setup(on_attach, capabilities)
  local lspconfig = require("lspconfig")

  lspconfig.rust_analyzer.setup({
    on_attach = on_attach,
    capabilities = capabilities,
    settings = {
      ["rust-analyzer"] = {
        -- 启用所有功能
        checkOnSave = {
          command = "clippy", -- 使用 clippy 进行检查
          extraArgs = { "--all", "--", "-W", "clippy::all" },
        },
        cargo = {
          allFeatures = true,
          loadOutDirsFromCheck = true,
          runBuildScripts = true,
        },
        procMacro = {
          enable = true,
        },
        diagnostics = {
          enable = true,
          experimental = {
            enable = true,
          },
        },
        hover = {
          actions = {
            references = {
              enable = true,
            },
          },
        },
      },
    },
  })
end

return M
