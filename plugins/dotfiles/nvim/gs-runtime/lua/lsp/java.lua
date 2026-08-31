-- Global Scripts Configuration
-- Generated automatically - do not edit manually
-- Generated at: 2026-03-23 15:40:42
-- Configuration source: /Users/solo/code/github/global_scripts

-- ============================================
-- Java LSP 配置模块 (jdtls)
-- 目标：
-- 1) 工作区缓存完全放到 Neovim data 目录，避免污染 Git 工程目录
-- 2) Java 输出目录统一到 build/classes（接近 Android Studio/Gradle）
-- 3) 按 Java 文件打开时加载
-- ============================================

local M = {}

local lsp_util = require("lspconfig.util")

local function resolve_jdtls_config_path(jdtls_path)
  if vim.fn.has("mac") == 1 then
    local arch = vim.loop.os_uname().machine
    if arch == "arm64" then
      return jdtls_path .. "/config_mac_arm"
    end
    return jdtls_path .. "/config_mac"
  end

  if vim.fn.has("unix") == 1 then
    local arch = vim.loop.os_uname().machine
    if arch == "aarch64" or arch == "arm64" then
      return jdtls_path .. "/config_linux_arm"
    end
    return jdtls_path .. "/config_linux"
  end

  return jdtls_path .. "/config_win"
end

local function find_module_root(bufname)
  local module_root = lsp_util.root_pattern(
    "build.gradle",
    "build.gradle.kts",
    "pom.xml",
    "mvnw",
    "gradlew"
  )(bufname)

  if module_root then
    return module_root
  end

  local fallback_root = lsp_util.root_pattern("settings.gradle", "settings.gradle.kts", ".git")(bufname)
  return fallback_root or vim.fn.getcwd()
end

local function make_workspace_dir(module_root)
  local workspace_dir = module_root .. "/build/.jdtls/workspace"
  vim.fn.mkdir(workspace_dir, "p")
  return workspace_dir
end

function M.setup(on_attach, capabilities)
  local group = vim.api.nvim_create_augroup("GS_Jdtls", { clear = true })

  vim.api.nvim_create_autocmd("FileType", {
    group = group,
    pattern = "java",
    callback = function()
      local ok_jdtls, jdtls = pcall(require, "jdtls")
      if not ok_jdtls then
        vim.notify("nvim-jdtls is not installed", vim.log.levels.WARN)
        return
      end

      local bufname = vim.api.nvim_buf_get_name(0)
      local module_root = find_module_root(bufname)

      local home = vim.env.HOME or ""
      local jdtls_path = home .. "/.local/share/nvim/mason/packages/jdtls"
      local config_path = resolve_jdtls_config_path(jdtls_path)
      local workspace_dir = make_workspace_dir(module_root)

      local jdtls_capabilities = vim.deepcopy(capabilities)
      jdtls_capabilities.offsetEncoding = { "utf-16" }

      local config = {
        cmd = {
          "java",
          "-Declipse.application=org.eclipse.jdt.ls.core.id1",
          "-Dosgi.bundles.defaultStartLevel=4",
          "-Declipse.product=org.eclipse.jdt.ls.core.product",
          "-Dlog.protocol=false",
          "-Dlog.level=WARN",
          "-Xms512m",
          "--add-modules=ALL-SYSTEM",
          "--add-opens", "java.base/java.util=ALL-UNNAMED",
          "--add-opens", "java.base/java.lang=ALL-UNNAMED",
          "-jar", vim.fn.glob(jdtls_path .. "/plugins/org.eclipse.equinox.launcher_*.jar"),
          "-configuration", config_path,
          "-data", workspace_dir,
        },
        root_dir = module_root,
        capabilities = jdtls_capabilities,
        flags = {
          allow_incremental_sync = true,
        },
        init_options = {
          bundles = {},
        },
        settings = {
          java = {
            autobuild = { enabled = false },
            project = {
              outputPath = "build/classes",
            },
            configuration = {
              updateBuildConfiguration = "interactive",
            },
            import = {
              gradle = { enabled = true },
              maven = { enabled = true },
              exclusions = {
                "**/node_modules/**",
                "**/.metadata/**",
                "**/archetype-resources/**",
                "**/META-INF/maven/**",
              },
            },
            maven = { downloadSources = true },
            eclipse = { downloadSources = true },
            implementationsCodeLens = { enabled = true },
            referencesCodeLens = { enabled = true },
            references = { includeDecompiledSources = true },
            format = { enabled = true },
            signatureHelp = { enabled = true },
            contentProvider = { preferred = "fernflower" },
            sources = {
              organizeImports = {
                starThreshold = 9999,
                staticStarThreshold = 9999,
              },
            },
            codeGeneration = {
              toString = {
                template = "${object.className}{${member.name()}=${member.value}, ${otherMembers}}",
              },
              useBlocks = true,
            },
          },
        },
        on_attach = function(client, bufnr)
          on_attach(client, bufnr)

          pcall(function()
            jdtls.setup_dap({ hotcodereplace = "auto" })
          end)

          vim.keymap.set("n", "<leader>jo", jdtls.organize_imports, { buffer = bufnr, desc = "Java organize imports" })
          vim.keymap.set("n", "<leader>jv", jdtls.extract_variable, { buffer = bufnr, desc = "Java extract variable" })
          vim.keymap.set("v", "<leader>jv", [[<ESC><CMD>lua require('jdtls').extract_variable(true)<CR>]], { buffer = bufnr, desc = "Java extract variable" })
          vim.keymap.set("n", "<leader>jc", jdtls.extract_constant, { buffer = bufnr, desc = "Java extract constant" })
          vim.keymap.set("v", "<leader>jc", [[<ESC><CMD>lua require('jdtls').extract_constant(true)<CR>]], { buffer = bufnr, desc = "Java extract constant" })
          vim.keymap.set("v", "<leader>jm", [[<ESC><CMD>lua require('jdtls').extract_method(true)<CR>]], { buffer = bufnr, desc = "Java extract method" })
          vim.keymap.set("n", "<leader>ju", "<CMD>JdtUpdateConfig<CR>", { buffer = bufnr, desc = "Java update config" })
        end,
      }

      jdtls.start_or_attach(config)
    end,
  })
end

return M
