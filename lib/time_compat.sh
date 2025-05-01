#!/bin/bash
# 跨平台高精度时间获取脚本 - lib/time_compat.sh
# 支持秒、毫秒、微秒精度，兼容 Linux/macOS/BSD 等系统

# 检测系统类型
SYSTEM_TYPE="unknown"
case "$(uname -s)" in
    Linux*)     SYSTEM_TYPE="linux" ;;
    Darwin*)    SYSTEM_TYPE="macos" ;;
    FreeBSD*|OpenBSD*|NetBSD*) SYSTEM_TYPE="bsd" ;;
    CYGWIN*|MINGW*|MSYS*) SYSTEM_TYPE="windows" ;;
    *) SYSTEM_TYPE="unknown" ;;
esac

# 检测可用的时间获取方法
TIME_METHOD="date_s"  # 默认使用秒级精度

# 检测高精度时间支持
_detect_time_capabilities() {
    # 检测 date 命令的纳秒支持 (GNU coreutils)
    # 注意：macOS 的 date 不支持 %N，会原样输出 "%N"
    local test_ns
    test_ns=$(date +%N 2>/dev/null)
    if [[ "$test_ns" != "%N" ]] && [[ "$test_ns" =~ ^[0-9]+$ ]]; then
        TIME_METHOD="date_ns"
        return 0
    fi
    
    # macOS 特殊方法：检测 gdate (GNU coreutils)
    if [[ "$SYSTEM_TYPE" == "macos" ]] && command -v gdate >/dev/null 2>&1; then
        local test_gdate_ns
        test_gdate_ns=$(gdate +%N 2>/dev/null)
        if [[ "$test_gdate_ns" != "%N" ]] && [[ "$test_gdate_ns" =~ ^[0-9]+$ ]]; then
            TIME_METHOD="gdate_ns"
            return 0
        fi
    fi
    
    # 检测 Python 支持
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import time; print(int(time.time() * 1000))" >/dev/null 2>&1; then
            TIME_METHOD="python3"
            return 0
        fi
    fi
    
    if command -v python >/dev/null 2>&1; then
        if python -c "import time; print(int(time.time() * 1000))" >/dev/null 2>&1; then
            TIME_METHOD="python"
            return 0
        fi
    fi
    
    # 检测 Perl 支持
    if command -v perl >/dev/null 2>&1; then
        if perl -MTime::HiRes -e 'print int(Time::HiRes::time() * 1000)' >/dev/null 2>&1; then
            TIME_METHOD="perl"
            return 0
        fi
    fi
    
    # 检测 Node.js 支持
    if command -v node >/dev/null 2>&1; then
        if node -e 'console.log(Date.now())' >/dev/null 2>&1; then
            TIME_METHOD="node"
            return 0
        fi
    fi
    
    # 检测 Ruby 支持
    if command -v ruby >/dev/null 2>&1; then
        if ruby -e 'puts (Time.now.to_f * 1000).to_i' >/dev/null 2>&1; then
            TIME_METHOD="ruby"
            return 0
        fi
    fi
    
    # macOS 特殊方法：使用 gdate (如果安装了 GNU coreutils)
    # 已经在上面检测过了，这里删除重复代码
    
    # 检测 /proc/timer_list (Linux specific)
    if [[ "$SYSTEM_TYPE" == "linux" ]] && [[ -r /proc/timer_list ]]; then
        TIME_METHOD="proc_timer"
        return 0
    fi
    
    # 最后回退到秒级精度
    TIME_METHOD="date_s"
}

# 初始化检测
_detect_time_capabilities

# 获取当前时间戳（毫秒）
gs_time_ms() {
    case "$TIME_METHOD" in
        "date_ns")
            # GNU date 支持纳秒
            date +%s%3N
            ;;
        "gdate_ns")
            # macOS 上的 GNU date
            gdate +%s%3N
            ;;
        "python3")
            python3 -c "import time; print(int(time.time() * 1000))"
            ;;
        "python")
            python -c "import time; print(int(time.time() * 1000))"
            ;;
        "perl")
            perl -MTime::HiRes -e 'print int(Time::HiRes::time() * 1000)'
            ;;
        "node")
            node -e 'console.log(Date.now())'
            ;;
        "ruby")
            ruby -e 'puts (Time.now.to_f * 1000).to_i'
            ;;
        "proc_timer")
            # Linux /proc/timer_list 方法（高级）
            awk '/now at/ {print int($3/1000000); exit}' /proc/timer_list 2>/dev/null || \
            echo $(($(date +%s) * 1000))
            ;;
        *)
            # 回退到秒级精度，转换为毫秒
            echo $(($(date +%s) * 1000))
            ;;
    esac
}

# 获取当前时间戳（微秒）
gs_time_us() {
    case "$TIME_METHOD" in
        "date_ns")
            date +%s%6N
            ;;
        "gdate_ns")
            gdate +%s%6N
            ;;
        "python3")
            python3 -c "import time; print(int(time.time() * 1000000))"
            ;;
        "python")
            python -c "import time; print(int(time.time() * 1000000))"
            ;;
        "perl")
            perl -MTime::HiRes -e 'print int(Time::HiRes::time() * 1000000)'
            ;;
        "node")
            node -e 'console.log(Math.floor(process.hrtime.bigint() / 1000n))'
            ;;
        "ruby")
            ruby -e 'puts (Time.now.to_f * 1000000).to_i'
            ;;
        *)
            echo $(($(gs_time_ms) * 1000))
            ;;
    esac
}

# 获取当前时间戳（纳秒）
gs_time_ns() {
    case "$TIME_METHOD" in
        "date_ns")
            date +%s%9N
            ;;
        "gdate_ns")
            gdate +%s%9N
            ;;
        "python3")
            python3 -c "import time; print(int(time.time() * 1000000000))"
            ;;
        "python")
            python -c "import time; print(int(time.time() * 1000000000))"
            ;;
        "perl")
            perl -MTime::HiRes -e 'print int(Time::HiRes::time() * 1000000000)'
            ;;
        "node")
            node -e 'console.log(process.hrtime.bigint())'
            ;;
        "ruby")
            ruby -e 'puts (Time.now.to_f * 1000000000).to_i'
            ;;
        *)
            echo $(($(gs_time_ms) * 1000000))
            ;;
    esac
}

# 获取当前时间戳（秒）
gs_time_s() {
    date +%s
}

# 计算时间差（毫秒）
gs_time_diff_ms() {
    local start_time="$1"
    local end_time="$2"
    echo $((end_time - start_time))
}

# 格式化时间差为可读格式
gs_time_format() {
    local duration_ms="$1"
    local unit="${2:-auto}"
    
    case "$unit" in
        "ns")
            echo "${duration_ms}000000ns"
            ;;
        "us")
            echo "${duration_ms}000μs"
            ;;
        "ms")
            echo "${duration_ms}ms"
            ;;
        "s")
            echo "$((duration_ms / 1000))s"
            ;;
        "auto")
            if [[ $duration_ms -lt 1000 ]]; then
                echo "${duration_ms}ms"
            elif [[ $duration_ms -lt 60000 ]]; then
                printf "%.2fs\n" "$(echo "scale=2; $duration_ms / 1000" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $duration_ms/1000}")"
            else
                local minutes=$((duration_ms / 60000))
                local seconds=$(((duration_ms % 60000) / 1000))
                echo "${minutes}m${seconds}s"
            fi
            ;;
    esac
}

# 简单的性能测试函数
gs_benchmark() {
    local description="$1"
    shift
    local command="$@"
    
    printf "测试: %s\n" "$description"
    
    local start_time end_time duration
    start_time=$(gs_time_ms)
    
    # 执行命令
    eval "$command"
    
    end_time=$(gs_time_ms)
    duration=$(gs_time_diff_ms "$start_time" "$end_time")
    
    printf "耗时: %s\n" "$(gs_time_format "$duration")"
    echo
}

# 批量性能测试
gs_benchmark_repeat() {
    local times="$1"
    local description="$2"
    shift 2
    local command="$@"
    
    printf "测试: %s (重复%d次)\n" "$description" "$times"
    
    local start_time end_time duration
    start_time=$(gs_time_ms)
    
    for ((i=1; i<=times; i++)); do
        eval "$command" >/dev/null 2>&1
    done
    
    end_time=$(gs_time_ms)
    duration=$(gs_time_diff_ms "$start_time" "$end_time")
    
    printf "总耗时: %s\n" "$(gs_time_format "$duration")"
    printf "平均耗时: %s\n" "$(gs_time_format $((duration / times)))"
    echo
}

# 导出系统信息
export SYSTEM_TYPE TIME_METHOD

# 时间兼容性信息
gs_time_info() {
    printf "系统类型: %s\n" "$SYSTEM_TYPE"
    printf "时间方法: %s\n" "$TIME_METHOD"
    case "$TIME_METHOD" in 
        date_ns|gdate_ns|python*|perl|node|ruby) 
            printf "精度支持: 毫秒/微秒/纳秒\n" 
            ;;
        *) 
            printf "精度支持: 毫秒（模拟）\n" 
            ;;
    esac
    
    printf "\n当前时间戳:\n"
    printf "  秒:   %s\n" "$(gs_time_s)"
    printf "  毫秒: %s\n" "$(gs_time_ms)"
    printf "  微秒: %s\n" "$(gs_time_us)"
    printf "  纳秒: %s\n" "$(gs_time_ns)"
}