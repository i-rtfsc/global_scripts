-- ============================================
-- 通用 LSP 配置
-- 用于简单语言：HTML, CSS, JSON, YAML, Bash, Docker 等
-- ============================================

local lspconfig = require("lspconfig")
local cmp_nvim_lsp = require("cmp_nvim_lsp")

-- 通用的 on_attach 函数
local on_attach = function(client, bufnr)
  local opts = { buffer = bufnr, silent = true }

  -- 通用编辑器设置（4 空格缩进）
  vim.opt_local.shiftwidth = 4
  vim.opt_local.tabstop = 4
  vim.opt_local.expandtab = true

  -- 根据文件类型设置不同的 textwidth
  local ft = vim.bo[bufnr].filetype
  if ft == "html" or ft == "css" or ft == "json" or ft == "yaml" then
    vim.opt_local.textwidth = 120
    vim.opt_local.colorcolumn = "120"
  elseif ft == "sh" or ft == "bash" then
    vim.opt_local.textwidth = 100
    vim.opt_local.colorcolumn = "100"
  end

  -- 代码折叠
  if ft == "json" or ft == "sh" or ft == "bash" then
    vim.opt_local.foldmethod = "syntax"
  else
    vim.opt_local.foldmethod = "indent"
  end
  vim.opt_local.foldlevelstart = 99

  -- 基础键位映射
  vim.keymap.set("n", "gd", vim.lsp.buf.definition, opts)
  vim.keymap.set("n", "K", vim.lsp.buf.hover, opts)
  vim.keymap.set("n", "gr", vim.lsp.buf.references, opts)
  vim.keymap.set({ "n", "v" }, "<leader>ca", vim.lsp.buf.code_action, opts)
  vim.keymap.set("n", "<leader>rn", vim.lsp.buf.rename, opts)
  vim.keymap.set("n", "<leader>d", vim.diagnostic.open_float, opts)
  vim.keymap.set("n", "[d", vim.diagnostic.goto_prev, opts)
  vim.keymap.set("n", "]d", vim.diagnostic.goto_next, opts)
end

-- 通用能力配置
local capabilities = cmp_nvim_lsp.default_capabilities()

-- 默认配置
local default_config = {
  capabilities = capabilities,
  on_attach = on_attach,
}

-- HTML
lspconfig.html.setup(default_config)

-- CSS
lspconfig.cssls.setup(default_config)

-- TailwindCSS
lspconfig.tailwindcss.setup(default_config)

-- JSON
lspconfig.jsonls.setup(vim.tbl_extend("force", default_config, {
  settings = {
    json = {
      schemas = require("schemastore").json.schemas(),
      validate = { enable = true },
    },
  },
}))

-- YAML
lspconfig.yamlls.setup(vim.tbl_extend("force", default_config, {
  settings = {
    yaml = {
      schemaStore = {
        enable = false,
        url = "",
      },
      schemas = require("schemastore").yaml.schemas(),
    },
  },
}))

-- Bash
lspconfig.bashls.setup(default_config)

-- Docker
lspconfig.dockerls.setup(default_config)

-- Dockerfile (docker-compose)
lspconfig.docker_compose_language_service.setup(default_config)
