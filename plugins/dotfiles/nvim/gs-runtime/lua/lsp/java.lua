-- ============================================
-- Java LSP 配置模块 (jdtls)
--
-- 注意：jdtls 比较特殊：
-- 1. 使用 nvim-jdtls 插件，不是 lspconfig
-- 2. 使用 jdtls.start_or_attach() 而不是 lspconfig.jdtls.setup()
-- 3. lspconfig 会自动创建 FileType autocmd，但 nvim-jdtls 不会，所以需要手动创建
-- ============================================

local M = {}

function M.setup(on_attach, capabilities)
  -- 立即检查当前所有 Java buffer，如果有旧的 jdtls 客户端，停止它
  for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_loaded(bufnr) and vim.bo[bufnr].filetype == "java" then
      local clients = vim.lsp.get_active_clients({ bufnr = bufnr, name = "jdtls" })
      for _, client in ipairs(clients) do
        vim.notify("立即停止旧的 jdtls 客户端 (ID: " .. client.id .. ")", vim.log.levels.WARN)
        vim.lsp.stop_client(client.id, true)
      end
    end
  end

  -- 创建 autocmd：在打开 Java 文件时启动 jdtls
  -- （这和 lspconfig 内部做的事情一样，只是我们要手动写）
  vim.api.nvim_create_autocmd("FileType", {
    pattern = "java",
    callback = function()
      -- ⚠️ 重要：停止任何已存在的 jdtls 客户端（可能是 mason-lspconfig 自动启动的）
      local clients = vim.lsp.get_active_clients({ bufnr = 0, name = "jdtls" })
      for _, client in ipairs(clients) do
        vim.notify("停止旧的 jdtls 客户端 (ID: " .. client.id .. ")", vim.log.levels.INFO)
        vim.lsp.stop_client(client.id, true)
      end

      -- 等待旧客户端完全停止
      vim.defer_fn(function()
        local home = os.getenv("HOME")

        -- 检查 nvim-jdtls 是否安装
        local jdtls_ok, jdtls = pcall(require, "jdtls")
        if not jdtls_ok then
          vim.notify("nvim-jdtls not installed", vim.log.levels.WARN)
          return
        end

        -- 为 jdtls 配置 capabilities（修复 position_encoding 警告）
        local jdtls_capabilities = vim.deepcopy(capabilities)
        jdtls_capabilities.offsetEncoding = { "utf-16" }

        -- 工作区目录：存放在项目的 build 目录下
        -- 这样所有 jdtls 生成的文件都在 build/ 下，方便清理
        local workspace_dir = vim.fn.getcwd() .. "/build/eclipse-workspace"

        -- 确保 build 目录存在
        vim.fn.mkdir(workspace_dir, "p")

        -- 查找 jdtls 安装路径（通过 Mason 安装）
        local mason_path = home .. "/.local/share/nvim/mason/packages"
        local jdtls_path = mason_path .. "/jdtls"

        -- 根据操作系统选择配置
        local config_path
        if vim.fn.has("mac") == 1 then
          config_path = jdtls_path .. "/config_mac"
        elseif vim.fn.has("unix") == 1 then
          config_path = jdtls_path .. "/config_linux"
        else
          config_path = jdtls_path .. "/config_win"
        end

        -- jdtls 配置
        local config = {
          -- 启动命令
          cmd = {
            "java",
            "-Declipse.application=org.eclipse.jdt.ls.core.id1",
            "-Dosgi.bundles.defaultStartLevel=4",
            "-Declipse.product=org.eclipse.jdt.ls.core.product",
            "-Dlog.protocol=true",
            "-Dlog.level=ALL",
            "-Xms1g",
            "--add-modules=ALL-SYSTEM",
            "--add-opens", "java.base/java.util=ALL-UNNAMED",
            "--add-opens", "java.base/java.lang=ALL-UNNAMED",

            "-jar", vim.fn.glob(jdtls_path .. "/plugins/org.eclipse.equinox.launcher_*.jar"),
            "-configuration", config_path,
            "-data", workspace_dir,
          },

          -- 项目根目录检测
          root_dir = require("jdtls.setup").find_root({ ".git", "mvnw", "gradlew", "pom.xml", "build.gradle" }),

          -- 设置
          settings = {
            java = {
              -- 自动构建（必须启用，否则 LSP 功能失效）
              autobuild = { enabled = true },

              -- 使用 Gradle/Maven 原生导入，减少 Eclipse 元数据生成
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

              -- Eclipse 相关配置
              eclipse = {
                downloadSources = true,
              },

              -- 配置文件位置（尽量使用项目原有配置）
              configuration = {
                updateBuildConfiguration = "interactive",
              },

              maven = {
                downloadSources = true,
              },
              implementationsCodeLens = {
                enabled = true,
              },
              referencesCodeLens = {
                enabled = true,
              },
              references = {
                includeDecompiledSources = true,
              },
              format = {
                enabled = true,
              },
              signatureHelp = { enabled = true },
              contentProvider = { preferred = "fernflower" },
              completion = {
                favoriteStaticMembers = {
                  "org.hamcrest.MatcherAssert.assertThat",
                  "org.hamcrest.Matchers.*",
                  "org.hamcrest.CoreMatchers.*",
                  "org.junit.jupiter.api.Assertions.*",
                  "java.util.Objects.requireNonNull",
                  "java.util.Objects.requireNonNullElse",
                  "org.mockito.Mockito.*",
                },
                filteredTypes = {
                  "com.sun.*",
                  "io.micrometer.shaded.*",
                  "java.awt.*",
                  "jdk.*",
                  "sun.*",
                },
              },
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

          -- 标志
          flags = {
            allow_incremental_sync = true,
          },

          -- 初始化选项
          init_options = {
            bundles = {},
          },

          -- 使用传入的 on_attach，并添加 Java 特定功能
          on_attach = function(client, bufnr)
            -- 调用统一的 on_attach（设置通用 LSP 键映射）
            on_attach(client, bufnr)

            -- 启用 jdtls 特定功能
            jdtls.setup_dap({ hotcodereplace = "auto" })

            -- Java 特定命令键映射
            vim.keymap.set("n", "<leader>jo", jdtls.organize_imports, { buffer = bufnr, desc = "Organize imports" })
            vim.keymap.set("n", "<leader>jv", jdtls.extract_variable, { buffer = bufnr, desc = "Extract variable" })
            vim.keymap.set("v", "<leader>jv", [[<ESC><CMD>lua require('jdtls').extract_variable(true)<CR>]], { buffer = bufnr, desc = "Extract variable" })
            vim.keymap.set("n", "<leader>jc", jdtls.extract_constant, { buffer = bufnr, desc = "Extract constant" })
            vim.keymap.set("v", "<leader>jc", [[<ESC><CMD>lua require('jdtls').extract_constant(true)<CR>]], { buffer = bufnr, desc = "Extract constant" })
            vim.keymap.set("v", "<leader>jm", [[<ESC><CMD>lua require('jdtls').extract_method(true)<CR>]], { buffer = bufnr, desc = "Extract method" })
            vim.keymap.set("n", "<leader>ju", "<CMD>JdtUpdateConfig<CR>", { buffer = bufnr, desc = "Update config" })

            -- 如果安装了 nvim-dap，设置调试
            local status_ok, dap = pcall(require, "dap")
            if status_ok then
              dap.configurations.java = {
                {
                  type = "java",
                  request = "attach",
                  name = "Debug (Attach) - Remote",
                  hostName = "127.0.0.1",
                  port = 5005,
                },
              }
            end
          end,

          -- 使用配置了 UTF-16 编码的 capabilities
          capabilities = jdtls_capabilities,
        }

        -- 启动或附加 jdtls（和 vim.lsp.start_client 类似）
        jdtls.start_or_attach(config)
      end, 500)  -- 等待 500ms 让旧客户端完全停止
    end,
  })
end

return M
