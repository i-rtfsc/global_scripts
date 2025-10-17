#!/usr/bin/env fish
# ============================================
# Fish Shell Plugins Setup Script
# 一次性安装所有推荐的 Fish Shell 插件
# ============================================

set_color cyan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🐟 Fish Shell Plugins Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
set_color normal
echo ""

# ============================================
# 1. 安装 Fisher 插件管理器
# ============================================
if functions -q fisher
    set_color green
    echo "✅ Fisher 已安装"
    set_color normal
else
    set_color yellow
    echo "📦 正在安装 Fisher 插件管理器..."
    set_color normal

    curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source
    fisher install jorgebucaran/fisher

    if functions -q fisher
        set_color green
        echo "✅ Fisher 安装成功"
        set_color normal
    else
        set_color red
        echo "❌ Fisher 安装失败"
        set_color normal
        exit 1
    end
end

echo ""

# ============================================
# 2. 安装核心插件
# ============================================
set_color yellow
echo "📦 正在安装核心插件..."
set_color normal
echo ""

set -l plugins \
    "IlanCosman/tide@v6:Modern prompt theme" \
    "jethrokuan/z:Directory jumping" \
    "PatrickF1/fzf.fish:Fuzzy finder integration" \
    "franciscolourenco/done:Command completion notification" \
    "laughedelic/pisces:Auto-close brackets" \
    "gazorby/fish-abbreviation-tips:Show abbreviation tips" \
    "edc/bass:Bash scripts in Fish"

set -l success_count 0
set -l fail_count 0

for plugin_info in $plugins
    set -l plugin (string split ':' $plugin_info)[1]
    set -l description (string split ':' $plugin_info)[2]

    set_color cyan
    echo "  Installing $plugin ($description)..."
    set_color normal

    # Check if already installed
    if fisher list | grep -q $plugin
        set_color brblack
        echo "    ⏭️  Already installed, skipping"
        set_color normal
        set success_count (math $success_count + 1)
    else
        # Install plugin
        if fisher install $plugin >/dev/null 2>&1
            set_color green
            echo "    ✅ Installed successfully"
            set_color normal
            set success_count (math $success_count + 1)
        else
            set_color red
            echo "    ❌ Installation failed"
            set_color normal
            set fail_count (math $fail_count + 1)
        end
    end
    echo ""
end

# ============================================
# 3. 安装结果总结
# ============================================
set_color cyan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  📊 Installation Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
set_color normal
echo ""

if test $fail_count -eq 0
    set_color green
    echo "  ✅ All plugins installed successfully! ($success_count/$success_count)"
    set_color normal
else
    set_color yellow
    echo "  ⚠️  Some plugins failed to install"
    echo "  Success: $success_count"
    echo "  Failed:  $fail_count"
    set_color normal
end

echo ""

# ============================================
# 4. 配置 Tide 提示符
# ============================================
if fisher list | grep -q "tide"
    set_color yellow
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  🎨 Tide Prompt Configuration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    set_color normal
    echo ""
    echo "  Tide 提示符已安装！"
    echo ""
    echo "  可选：运行以下命令自定义提示符样式："
    set_color cyan
    echo "    tide configure"
    set_color normal
    echo ""
end

# ============================================
# 5. 完成提示
# ============================================
set_color green
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🎉 Setup Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
set_color normal
echo ""
echo "  请重新加载 Fish Shell 以应用更改："
set_color cyan
echo "    exec fish"
set_color normal
echo ""
echo "  或重新启动终端"
echo ""
