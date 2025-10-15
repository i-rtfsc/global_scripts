#!/bin/bash

# Grep Plugin - Code Search Utilities
# 代码搜索工具插件 - 针对不同文件类型的智能grep功能

# @plugin_function
# name: help
# description:
#   zh: 显示所有可用的grep命令
#   en: Show all available grep commands
# usage: gs grep help
# examples:
#   - gs grep help
help() {
    cat <<EOF
📝 Grep Plugin - Code Search Utilities

🔍 Available Commands:
  all        - 在所有源代码文件中搜索 / Search in all source files
  c          - 在C/C++文件中搜索 / Search in C/C++ files  
  java       - 在Java文件中搜索 / Search in Java files
  kotlin     - 在Kotlin文件中搜索 / Search in Kotlin files
  go         - 在Go文件中搜索 / Search in Go files
  rust       - 在Rust文件中搜索 / Search in Rust files
  python     - 在Python文件中搜索 / Search in Python files
  js         - 在JavaScript文件中搜索 / Search in JavaScript files
  ts         - 在TypeScript文件中搜索 / Search in TypeScript files
  gradle     - 在Gradle文件中搜索 / Search in Gradle files
  make       - 在Makefile和构建文件中搜索 / Search in Makefiles and build files
  xml        - 在XML文件中搜索 / Search in XML files
  json       - 在JSON文件中搜索 / Search in JSON files
  yaml       - 在YAML文件中搜索 / Search in YAML files
  sh         - 在Shell脚本中搜索 / Search in shell scripts
  res        - 在Android资源文件中搜索 / Search in Android resource files
  manifest   - 在AndroidManifest.xml中搜索 / Search in AndroidManifest.xml
  rc         - 在配置文件(.rc)中搜索 / Search in .rc config files
  tree       - 在常见代码文件中搜索(不区分大小写) / Case-insensitive search in common code files

💡 Usage: gs grep <command> <search_pattern> [additional_grep_options]
📖 Examples:
  gs grep java "onCreate"
  gs grep c "malloc" -A 3 -B 1
  gs grep all "TODO" --color=always
EOF
}

# @plugin_function
# name: all
# description:
#   zh: 在所有源代码文件中搜索
#   en: Search in all source files
# usage: gs grep all <pattern> [grep_options]
# examples:
#   - gs grep all "function"
#   - gs grep all "TODO" -n
case $(uname -s) in
    Darwin)
        all() {
            find -E . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -name .vscode -prune -o -type f -iregex '.*\.(c|h|cc|cpp|hpp|cxx|hxx|S|java|kt|xml|sh|mk|aidl|vts|proto|py|js|ts|go|rs|swift|m|mm)' \
                -exec grep --color=auto -n "$@" {} +
        }
        ;;
    *)
        all() {
            find . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -name .vscode -prune -o -type f -iregex '.*\.\(c\|h\|cc\|cpp\|hpp\|cxx\|hxx\|S\|java\|kt\|xml\|sh\|mk\|aidl\|vts\|proto\|py\|js\|ts\|go\|rs\|swift\|m\|mm\)' \
                -exec grep --color=auto -n "$@" {} +
        }
        ;;
esac

# @plugin_function
# name: c
# description:
#   zh: 在C/C++文件中搜索
#   en: Search in C/C++ files
# usage: gs grep c <pattern> [grep_options]
# examples:
#   - gs grep c "malloc"
#   - gs grep c "struct" -A 2
c() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name node_modules -prune -o -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hpp' -o -name '*.hxx' \) \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: java
# description:
#   zh: 在Java文件中搜索
#   en: Search in Java files
# usage: gs grep java <pattern> [grep_options]
# examples:
#   - gs grep java "public class"
#   - gs grep java "onCreate"
java() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name node_modules -prune -o -type f -name "*.java" \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: kotlin
# description:
#   zh: 在Kotlin文件中搜索
#   en: Search in Kotlin files
# usage: gs grep kotlin <pattern> [grep_options]
# examples:
#   - gs grep kotlin "fun "
#   - gs grep kotlin "class.*Activity"
kotlin() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name node_modules -prune -o -type f -name "*.kt" \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: go
# description:
#   zh: 在Go文件中搜索
#   en: Search in Go files
# usage: gs grep go <pattern> [grep_options]
# examples:
#   - gs grep go "func "
#   - gs grep go "package main"
go() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name vendor -prune -o -name node_modules -prune -o -type f -name "*.go" \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: rust
# description:
#   zh: 在Rust文件中搜索
#   en: Search in Rust files
# usage: gs grep rust <pattern> [grep_options]
# examples:
#   - gs grep rust "fn "
#   - gs grep rust "struct.*{"
rust() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name target -prune -o -name node_modules -prune -o -type f -name "*.rs" \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: python
# description:
#   zh: 在Python文件中搜索
#   en: Search in Python files
# usage: gs grep python <pattern> [grep_options]
# examples:
#   - gs grep python "def "
#   - gs grep python "import.*pandas"
python() {
    find . -name .repo -prune -o -name .git -prune -o -name __pycache__ -prune -o -name "*.pyc" -prune -o -name node_modules -prune -o -type f -name "*.py" \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: js
# description:
#   zh: 在JavaScript文件中搜索
#   en: Search in JavaScript files
# usage: gs grep js <pattern> [grep_options]
# examples:
#   - gs grep js "function"
#   - gs grep js "const.*="
js() {
    find . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -name dist -prune -o -name build -prune -o -type f \( -name "*.js" -o -name "*.jsx" \) \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: ts
# description:
#   zh: 在TypeScript文件中搜索
#   en: Search in TypeScript files
# usage: gs grep ts <pattern> [grep_options]
# examples:
#   - gs grep ts "interface"
#   - gs grep ts "type.*="
ts() {
    find . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -name dist -prune -o -name build -prune -o -type f \( -name "*.ts" -o -name "*.tsx" \) \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: gradle
# description:
#   zh: 在Gradle文件中搜索
#   en: Search in Gradle files
# usage: gs grep gradle <pattern> [grep_options]
# examples:
#   - gs grep gradle "implementation"
#   - gs grep gradle "android.*{"
gradle() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name node_modules -prune -o -type f -name "*.gradle" \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: xml
# description:
#   zh: 在XML文件中搜索
#   en: Search in XML files
# usage: gs grep xml <pattern> [grep_options]
# examples:
#   - gs grep xml "android:layout"
#   - gs grep xml "<activity"
xml() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name node_modules -prune -o -type f -name "*.xml" \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: json
# description:
#   zh: 在JSON文件中搜索
#   en: Search in JSON files
# usage: gs grep json <pattern> [grep_options]
# examples:
#   - gs grep json "version"
#   - gs grep json "dependencies"
json() {
    find . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -name out -prune -o -type f -name "*.json" \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: yaml
# description:
#   zh: 在YAML文件中搜索
#   en: Search in YAML files
# usage: gs grep yaml <pattern> [grep_options]
# examples:
#   - gs grep yaml "name:"
#   - gs grep yaml "version.*:"
yaml() {
    find . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -name out -prune -o -type f \( -name "*.yml" -o -name "*.yaml" \) \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: sh
# description:
#   zh: 在Shell脚本中搜索
#   en: Search in shell scripts
# usage: gs grep sh <pattern> [grep_options]
# examples:
#   - gs grep sh "function"
#   - gs grep sh "#!/bin/bash"
sh() {
    find . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -name out -prune -o -type f \( -name "*.sh" -o -name "*.bash" -o -name "*.zsh" \) \
        -exec grep --color=auto -n "$@" {} +
}

case $(uname -s) in
    Darwin)
        # @plugin_function
        # name: make
        # description:
        #   zh: 在Makefile和构建文件中搜索
        #   en: Search in Makefiles and build files
        # usage: gs grep make <pattern> [grep_options]
        # examples:
        #   - gs grep make "target:"
        #   - gs grep make "LOCAL_MODULE"
        make() {
            find -E . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -name node_modules -prune -o \( -iregex '.*/(Makefile|Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color=auto -n "$@" {} +
        }

        # @plugin_function
        # name: tree
        # description:
        #   zh: 在常见代码文件中搜索(不区分大小写)
        #   en: Case-insensitive search in common code files
        # usage: gs grep tree <pattern> [grep_options]
        # examples:
        #   - gs grep tree "TODO"
        #   - gs grep tree "fixme"
        tree() {
            find -E . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -type f -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml|py|js|ts|go|rs)' \
                -exec grep --color=auto -n -i "$@" {} +
        }
        ;;
    *)
        make() {
            find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -name node_modules -prune -o \( -regextype posix-egrep -iregex '(.*\/Makefile|.*\/Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regextype posix-extended -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color=auto -n "$@" {} +
        }

        tree() {
            find . -name .repo -prune -o -name .git -prune -o -name node_modules -prune -o -regextype posix-egrep -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml|py|js|ts|go|rs)' -type f \
                -exec grep --color=auto -n -i "$@" {} +
        }
        ;;
esac

# Android-specific grep functions

# @plugin_function
# name: res
# description:
#   zh: 在Android资源文件中搜索
#   en: Search in Android resource files
# usage: gs grep res <pattern> [grep_options]
# examples:
#   - gs grep res "string name"
#   - gs grep res "android:text"
res() {
    local dir
    for dir in $(find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name node_modules -prune -o -name res -type d -print); do
        find "$dir" -type f -name '*.xml' -exec grep --color=auto -n "$@" {} +
    done
}

# @plugin_function
# name: manifest
# description:
#   zh: 在AndroidManifest.xml中搜索
#   en: Search in AndroidManifest.xml files
# usage: gs grep manifest <pattern> [grep_options]
# examples:
#   - gs grep manifest "activity"
#   - gs grep manifest "permission"
manifest() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -name node_modules -prune -o -type f -name 'AndroidManifest.xml' \
        -exec grep --color=auto -n "$@" {} +
}

# @plugin_function
# name: rc
# description:
#   zh: 在配置文件(.rc)中搜索
#   en: Search in .rc config files
# usage: gs grep rc <pattern> [grep_options]
# examples:
#   - gs grep rc "service"
#   - gs grep rc "on boot"
rc() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name node_modules -prune -o -type f -name "*.rc*" \
        -exec grep --color=auto -n "$@" {} +
}

# Main dispatcher - handle function calls when script is executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -gt 0 ]]; then
        case "$1" in
            help|all|c|java|kotlin|go|rust|python|js|ts|gradle|make|xml|json|yaml|sh|res|manifest|rc|tree)
                "$@"
                ;;
            *)
                echo "❌ Unknown function: $1"
                echo "Run 'gs grep help' to see available commands"
                exit 1
                ;;
        esac
    else
        help
    fi
fi