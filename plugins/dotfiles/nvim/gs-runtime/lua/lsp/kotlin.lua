-- Global Scripts Configuration
-- Generated automatically - do not edit manually
-- Generated at: 2026-03-23 15:40:42
-- Configuration source: /Users/solo/code/github/global_scripts

-- ============================================
-- Kotlin LSP 配置模块
-- 目标：
-- 1) 只使用 kotlin-lsp，避免 kotlin-language-server 生成 Eclipse 元数据
-- 2) 所有缓存与索引都落到模块 build/.kotlin-lsp 下
-- 3) 自动清理模块根目录中的 .classpath/.project/.settings
-- ============================================

local M = {}

function M.setup(on_attach, capabilities)
  -- 防重入：某些发行版/插件重载场景会重复执行 setup，导致同一语言服务器被注册多次。
  if vim.g.gs_kotlin_lsp_setup_done then
    return
  end
  vim.g.gs_kotlin_lsp_setup_done = true

  local lspconfig = require("lspconfig")
  local configs = require("lspconfig.configs")
  local util = require("lspconfig.util")

  local mason_bin = vim.fn.stdpath("data") .. "/mason/bin"
  local kotlin_lsp_bin = mason_bin .. "/kotlin-lsp"

  local function is_executable(path)
    return vim.fn.executable(path) == 1
  end

  local function find_module_root(fname)
    local module_root = util.root_pattern(
      "build.gradle.kts",
      "build.gradle",
      "pom.xml",
      "gradlew",
      "mvnw"
    )(fname)

    return module_root
  end
  local function stop_duplicate_kotlin_clients_global()
    local keep = nil
    for _, client in ipairs(vim.lsp.get_active_clients()) do
      if client.name == "kotlin_lsp" then
        if keep == nil then
          keep = client.id
        else
          vim.lsp.stop_client(client.id, true)
        end
      end
    end
  end


  local function cleanup_eclipse_metadata(root_dir)
    if not root_dir or root_dir == "" then
      return
    end

    local targets = {
      root_dir .. "/.classpath",
      root_dir .. "/.project",
      root_dir .. "/.settings/org.eclipse.buildship.core.prefs",
    }

    for _, t in ipairs(targets) do
      if vim.fn.filereadable(t) == 1 then
        pcall(vim.fn.delete, t)
      end
    end

    local settings_dir = root_dir .. "/.settings"
    if vim.fn.isdirectory(settings_dir) == 1 then
      local remain = vim.fn.globpath(settings_dir, "*", false, true)
      if #remain == 0 then
        pcall(vim.fn.delete, settings_dir, "d")
      end
    end
  end

  local function cleanup_orphan_kotlin_processes()
    vim.fn.system({ "pkill", "-f", "mason/packages/kotlin-language-server" })
    vim.fn.system({ "pkill", "-f", "mason/packages/kotlin-lsp" })
  end

  local function dedupe_kotlin_clients(root_dir, keep_client_id)
    local seen_keep = false
    for _, client in ipairs(vim.lsp.get_active_clients()) do
      if (client.name == "kotlin_lsp" or client.name == "kotlin_language_server")
        and client.config and client.config.root_dir == root_dir then
        if client.id == keep_client_id and not seen_keep then
          seen_keep = true
        else
          vim.lsp.stop_client(client.id, true)
        end
      end
    end
  end

  local function stop_kotlin_clients_if_no_kotlin_buffers()
    for _, b in ipairs(vim.api.nvim_list_bufs()) do
      if vim.api.nvim_buf_is_loaded(b) and vim.bo[b].filetype == "kotlin" then
        return
      end
    end

    for _, c in ipairs(vim.lsp.get_active_clients()) do
      if c.name == "kotlin_lsp" or c.name == "kotlin_language_server" then
        vim.lsp.stop_client(c.id, true)
      end
    end
  end

  local function build_scoped_env(root_dir)
    local base = root_dir .. "/build/.kotlin-lsp"
    local gradle_home = root_dir .. "/build/.gradle-user-home"
    vim.fn.mkdir(base .. "/cache", "p")
    vim.fn.mkdir(base .. "/data", "p")
    vim.fn.mkdir(base .. "/state", "p")
    vim.fn.mkdir(gradle_home, "p")

    return {
      XDG_CACHE_HOME = base .. "/cache",
      XDG_DATA_HOME = base .. "/data",
      XDG_STATE_HOME = base .. "/state",
      JAVA_TOOL_OPTIONS = "-Xms128m -Xmx768m -XX:ActiveProcessorCount=2",
      GRADLE_USER_HOME = gradle_home,
      -- 尽量避免常驻 Gradle Daemon，并限制 Gradle 并发与内存。
      GRADLE_OPTS = "-Dorg.gradle.daemon=false -Dorg.gradle.workers.max=2 -Dorg.gradle.jvmargs=-Xmx512m",
    }
  end

  if not configs.kotlin_lsp then
    configs.kotlin_lsp = {
      default_config = {
        cmd = { kotlin_lsp_bin, "--stdio" },
        filetypes = { "kotlin" },
        root_dir = find_module_root,
        single_file_support = false,
      },
      docs = {
        description = "JetBrains Kotlin LSP",
      },
    }
  end

  cleanup_orphan_kotlin_processes()
  stop_duplicate_kotlin_clients_global()

  local aug = vim.api.nvim_create_augroup("GS_KotlinCleanup", { clear = true })
  vim.api.nvim_create_autocmd({ "BufDelete", "BufWipeout", "BufHidden" }, {
    group = aug,
    callback = function()
      vim.defer_fn(stop_kotlin_clients_if_no_kotlin_buffers, 120)
    end,
  })

  vim.api.nvim_create_autocmd("VimLeavePre", {
    group = aug,
    callback = function()
      cleanup_orphan_kotlin_processes()
    end,
  })

  if not is_executable(kotlin_lsp_bin) then
    vim.notify("kotlin-lsp binary not found in Mason bin; run :MasonInstall kotlin-lsp", vim.log.levels.WARN)
    return
  end

  lspconfig.kotlin_lsp.setup({
    on_attach = function(client, bufnr)
      local root = client.config and client.config.root_dir or nil
      dedupe_kotlin_clients(root, client.id)
      cleanup_eclipse_metadata(root)
      on_attach(client, bufnr)
    end,
    capabilities = capabilities,
    filetypes = { "kotlin" },
    root_dir = find_module_root,
    single_file_support = false,
    on_new_config = function(new_config, root_dir)
      cleanup_eclipse_metadata(root_dir)
      new_config.cmd = { kotlin_lsp_bin, "--stdio", "--system-path", root_dir .. "/build/.kotlin-lsp" }
      new_config.cmd_env = vim.tbl_extend("force", new_config.cmd_env or {}, build_scoped_env(root_dir))
    end,
  })
end

return M
