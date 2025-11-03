-- ============================================
-- C/C++ LSP 配置模块
-- ============================================

local M = {}

function M.setup(on_attach, capabilities)
  local lspconfig = require("lspconfig")

  -- 修复 position_encoding 警告（支持 UTF-16）
  local clangd_capabilities = vim.deepcopy(capabilities)
  clangd_capabilities.offsetEncoding = { "utf-16" }

  lspconfig.clangd.setup({
    on_attach = on_attach,
    capabilities = clangd_capabilities,
    cmd = {
      "clangd",
      "--background-index",
      "--clang-tidy",
      "--header-insertion=iwyu",
      "--completion-style=detailed",
      "--function-arg-placeholders",
      "--fallback-style=llvm",
      "--offset-encoding=utf-16",
    },
    init_options = {
      usePlaceholders = true,
      completeUnimported = true,
      clangdFileStatus = true,
    },
    filetypes = { "c", "cpp", "objc", "objcpp", "cuda", "proto" },
  })
end

return M
