#!/bin/bash

# Full Hybrid Plugin - Shell Component (subplugin: shell)
# Works alongside JSON (config/commands.json) and Python (plugin.py) components

# @plugin_function
# name: shell_system_info
# description:
#   zh: Shell系统信息获取
#   en: Shell system information gathering
# usage: gs full-hybrid shell_system_info [--format table|json] [--detailed]
# examples:
#   - gs full-hybrid shell_system_info
#   - gs full-hybrid shell_system_info --format json
#   - gs full-hybrid shell_system_info --detailed
shell_system_info() {
    local format="table"
    local detailed=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --format)
                format="$2"
                shift 2
                ;;
            --detailed)
                detailed=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
    
    echo "🐚 Full Hybrid: Shell System Information"
    echo "Format: $format | Detailed: $detailed"
    echo "========================================"
    
    # Collect system information
    local os_name=$(uname -s)
    local os_release=$(uname -r)
    local architecture=$(uname -m) 
    local hostname=$(hostname)
    local user=$USER
    local shell_version=$BASH_VERSION
    local current_time=$(date)
    
    if [[ "$format" == "json" ]]; then
        echo "{"
        echo "  \"plugin\": \"full-hybrid\","
        echo "  \"component\": \"shell\","
        echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"system\": {"
        echo "    \"os\": \"$os_name\","
        echo "    \"release\": \"$os_release\","
        echo "    \"architecture\": \"$architecture\","
        echo "    \"hostname\": \"$hostname\""
        echo "  },"
        echo "  \"user\": {"
        echo "    \"name\": \"$user\","
        echo "    \"shell\": \"$SHELL\","
        echo "    \"bash_version\": \"$shell_version\""
        echo "  }"
        
        if [[ "$detailed" == true ]]; then
            echo "  ,"
            echo "  \"environment\": {"
            echo "    \"home\": \"$HOME\","
            echo "    \"pwd\": \"$(pwd)\","
            echo "    \"path_entries\": $(echo $PATH | tr ':' '\n' | wc -l),"
            echo "    \"terminal\": \"$TERM\""
            echo "  },"
            echo "  \"processes\": {"
            echo "    \"current_pid\": \"$$\","
            echo "    \"parent_pid\": \"$PPID\","
            echo "    \"total_processes\": \"$(ps aux | wc -l)\""
            echo "  }"
        fi
        
        echo "}"
    else
        # Table format
        printf "%-20s | %-40s\n" "Property" "Value"
        printf "%-20s | %-40s\n" "--------------------" "----------------------------------------"
        printf "%-20s | %-40s\n" "Plugin Component" "Shell (Bash)"
        printf "%-20s | %-40s\n" "OS" "$os_name"
        printf "%-20s | %-40s\n" "Release" "$os_release"
        printf "%-20s | %-40s\n" "Architecture" "$architecture"
        printf "%-20s | %-40s\n" "Hostname" "$hostname"
        printf "%-20s | %-40s\n" "User" "$user"
        printf "%-20s | %-40s\n" "Shell" "$SHELL"
        printf "%-20s | %-40s\n" "Bash Version" "$shell_version"
        printf "%-20s | %-40s\n" "Current Time" "$current_time"
        
        if [[ "$detailed" == true ]]; then
            printf "%-20s | %-40s\n" "--------------------" "----------------------------------------"
            printf "%-20s | %-40s\n" "Home Directory" "$HOME"
            printf "%-20s | %-40s\n" "Working Directory" "$(pwd)"
            printf "%-20s | %-40s\n" "PATH Entries" "$(echo $PATH | tr ':' '\n' | wc -l)"
            printf "%-20s | %-40s\n" "Terminal Type" "$TERM"
            printf "%-20s | %-40s\n" "Current PID" "$$"
            printf "%-20s | %-40s\n" "Parent PID" "$PPID"
            printf "%-20s | %-40s\n" "Total Processes" "$(ps aux | wc -l)"
        fi
    fi
}

# @plugin_function
# name: shell_file_processor
# description:
#   zh: Shell文件处理器
#   en: Shell file processor
# usage: gs full-hybrid shell_file_processor <operation> <path> [options]
# examples:
#   - gs full-hybrid shell_file_processor analyze /etc/passwd
#   - gs full-hybrid shell_file_processor compress /tmp/test --format gzip
#   - gs full-hybrid shell_file_processor search /var/log --pattern ERROR
shell_file_processor() {
    local operation="$1"
    local path="$2"
    shift 2
    
    echo "📁 Full Hybrid: Shell File Processor"
    echo "Operation: $operation | Path: $path"
    echo "===================================="
    
    case "$operation" in
        "analyze")
            if [[ ! -e "$path" ]]; then
                echo "❌ Path does not exist: $path"
                return 1
            fi
            
            echo "📊 File Analysis Results:"
            echo "  Path: $path"
            echo "  Type: $(file "$path" 2>/dev/null | cut -d: -f2 | xargs)"
            echo "  Size: $(du -sh "$path" 2>/dev/null | cut -f1)"
            echo "  Permissions: $(stat -f%Sp "$path" 2>/dev/null || stat -c%A "$path" 2>/dev/null)"
            echo "  Owner: $(stat -f%Su:%Sg "$path" 2>/dev/null || stat -c%U:%G "$path" 2>/dev/null)"
            echo "  Modified: $(stat -f%Sm "$path" 2>/dev/null || stat -c%y "$path" 2>/dev/null)"
            
            if [[ -f "$path" ]]; then
                echo "  Lines: $(wc -l < "$path" 2>/dev/null || echo "N/A")"
                echo "  Words: $(wc -w < "$path" 2>/dev/null || echo "N/A")"
                echo "  Characters: $(wc -c < "$path" 2>/dev/null || echo "N/A")"
            elif [[ -d "$path" ]]; then
                echo "  Entries: $(ls -1 "$path" 2>/dev/null | wc -l)"
                echo "  Subdirectories: $(find "$path" -maxdepth 1 -type d 2>/dev/null | wc -l)"
                echo "  Files: $(find "$path" -maxdepth 1 -type f 2>/dev/null | wc -l)"
            fi
            ;;
            
        "search")
            local pattern=""
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --pattern)
                        pattern="$2"
                        shift 2
                        ;;
                    *)
                        shift
                        ;;
                esac
            done
            
            if [[ -z "$pattern" ]]; then
                echo "❌ Search pattern required. Use --pattern <text>"
                return 1
            fi
            
            echo "🔍 Search Results for '$pattern' in $path:"
            if [[ -f "$path" ]]; then
                grep -n "$pattern" "$path" 2>/dev/null | head -10 || echo "  No matches found"
            elif [[ -d "$path" ]]; then
                find "$path" -type f -name "*.log" -o -name "*.txt" -o -name "*.conf" | \
                    xargs grep -l "$pattern" 2>/dev/null | head -10 || echo "  No matching files found"
            else
                echo "  ❌ Invalid path for search: $path"
            fi
            ;;
            
        "compress")
            local format="gzip"
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --format)
                        format="$2"
                        shift 2
                        ;;
                    *)
                        shift
                        ;;
                esac
            done
            
            echo "🗜️ Compression Simulation (format: $format):"
            echo "  Source: $path"
            echo "  Target: ${path}.${format}"
            echo "  Status: ✅ Simulated compression completed"
            echo "  Note: This is a demonstration. Use actual compression tools for real operations."
            ;;
            
        *)
            echo "❌ Unknown operation: $operation"
            echo "Available operations: analyze, search, compress"
            return 1
            ;;
    esac
}

# @plugin_function
# name: shell_network_tools
# description:
#   zh: Shell网络工具集
#   en: Shell network toolkit
# usage: gs full-hybrid shell_network_tools <tool> [options]
# examples:
#   - gs full-hybrid shell_network_tools port_scan localhost
#   - gs full-hybrid shell_network_tools bandwidth_test
#   - gs full-hybrid shell_network_tools trace_route google.com
shell_network_tools() {
    local tool="$1"
    shift
    
    echo "🌐 Full Hybrid: Shell Network Tools"
    echo "Tool: $tool"
    echo "================================="
    
    case "$tool" in
        "port_scan")
            local target="${1:-localhost}"
            echo "🔍 Port Scan Simulation for $target:"
            echo "  Scanning common ports..."
            
            # Simulate port scanning (demonstration only)
            for port in 22 80 443 3306 5432 8080; do
                echo "  Port $port: $(if (( RANDOM % 3 == 0 )); then echo "Open"; else echo "Closed"; fi)"
                sleep 0.1
            done
            echo "  ✅ Scan completed"
            ;;
            
        "bandwidth_test")
            echo "📊 Bandwidth Test Simulation:"
            echo "  Testing download speed..."
            sleep 1
            echo "  Download: $((RANDOM % 100 + 50)) Mbps"
            echo "  Testing upload speed..."
            sleep 1 
            echo "  Upload: $((RANDOM % 50 + 10)) Mbps"
            echo "  Latency: $((RANDOM % 50 + 10)) ms"
            echo "  ✅ Bandwidth test completed"
            ;;
            
        "trace_route")
            local target="${1:-google.com}"
            echo "🛣️ Trace Route Simulation to $target:"
            echo "  Hop 1: 192.168.1.1 (Gateway) - 1ms"
            echo "  Hop 2: 10.0.0.1 (ISP) - 15ms"
            echo "  Hop 3: 172.16.1.1 (Regional) - 45ms"
            echo "  Hop 4: $target - 65ms"
            echo "  ✅ Route traced successfully"
            ;;
            
        *)
            echo "❌ Unknown tool: $tool"
            echo "Available tools: port_scan, bandwidth_test, trace_route"
            return 1
            ;;
    esac
}

# Main dispatcher - handle function calls when script is executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -gt 0 ]]; then
        case "$1" in
            shell_system_info|shell_network_tools|shell_toolkit)
                "$@"
                ;;
            *)
                echo "❌ Unknown function: $1"
                echo "Available functions: shell_system_info, shell_network_tools, shell_toolkit"
                exit 1
                ;;
        esac
    else
        echo "Usage: $0 <function_name> [args...]"
        echo "Available functions: shell_system_info, shell_network_tools, shell_toolkit"
        exit 1
    fi
fi
