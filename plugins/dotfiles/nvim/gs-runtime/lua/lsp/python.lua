-- ============================================
-- Python LSP 配置模块
-- ============================================

local M = {}

function M.setup(on_attach, capabilities)
  local lspconfig = require("lspconfig")

  lspconfig.pyright.setup({
    on_attach = on_attach,
    capabilities = capabilities,
    settings = {
      python = {
        analysis = {
          typeCheckingMode = "basic", -- "off", "basic", "strict"
          autoSearchPaths = true,
          useLibraryCodeForTypes = true,
          diagnosticMode = "workspace",
          -- 忽略某些诊断
          diagnosticSeverityOverrides = {
            reportUnusedImport = "warning",
            reportUnusedVariable = "warning",
            reportDuplicateImport = "warning",
          },
        },
      },
    },
  })
end

return M
