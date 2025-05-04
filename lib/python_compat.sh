#!/bin/bash
# Global Scripts V3 - Python兼容性检测和调用接口  
# 作者: Solo
# 版本: 1.0.0
# 描述: 检测Python环境，提供统一的Python调用接口

# 全局Python配置
_GS_PYTHON_CMD=""
_GS_PYTHON_VERSION=""
_GS_PYTHON_AVAILABLE="false"

# 检测Python环境
gs_python_detect() {
    local python_cmd=""
    
    # 优先级检测：python3 > python > python2
    if command -v python3 >/dev/null 2>&1; then
        python_cmd="python3"
        _GS_PYTHON_VERSION="3"
    elif command -v python >/dev/null 2>&1; then
        # 检查python版本
        local version
        version=$(python -c "import sys; print(sys.version_info[0])" 2>/dev/null)
        if [[ "$version" == "3" ]]; then
            python_cmd="python"
            _GS_PYTHON_VERSION="3"
        elif [[ "$version" == "2" ]]; then
            python_cmd="python"
            _GS_PYTHON_VERSION="2"
        fi
    elif command -v python2 >/dev/null 2>&1; then
        python_cmd="python2"
        _GS_PYTHON_VERSION="2"
    fi
    
    # 设置全局Python命令
    _GS_PYTHON_CMD="$python_cmd"
    
    # 检测基本功能可用性
    if [[ -n "$_GS_PYTHON_CMD" ]]; then
        if gs_python_test_basic; then
            _GS_PYTHON_AVAILABLE="true"
            gs_log_debug "Python环境检测成功: $_GS_PYTHON_CMD (version $_GS_PYTHON_VERSION)"
        else
            _GS_PYTHON_AVAILABLE="false"
            gs_log_warn "Python基本功能测试失败"
        fi
    else
        _GS_PYTHON_AVAILABLE="false"
        gs_log_warn "未找到可用的Python环境"
    fi
}

# 测试Python基本功能
gs_python_test_basic() {
    if [[ -z "$_GS_PYTHON_CMD" ]]; then
        return 1
    fi
    
    # 测试JSON支持
    if ! $_GS_PYTHON_CMD -c "import json; print('test')" >/dev/null 2>&1; then
        gs_log_warn "Python JSON模块不可用"
        return 1
    fi
    
    # 测试文件操作
    if ! $_GS_PYTHON_CMD -c "import os; print('test')" >/dev/null 2>&1; then
        gs_log_warn "Python OS模块不可用"
        return 1
    fi
    
    return 0
}

# Python辅助脚本调用接口
gs_python_call() {
    local operation="$1"
    shift
    local args=("$@")
    
    # 检查Python是否可用
    if [[ "$_GS_PYTHON_AVAILABLE" != "true" ]]; then
        gs_log_error "Python环境不可用，无法执行操作: $operation"
        return 1
    fi
    
    # 检查辅助脚本是否存在
    local helper_script="$_GS_ROOT/lib/gs_helper.py"
    if [[ ! -f "$helper_script" ]]; then
        gs_log_error "Python辅助脚本不存在: $helper_script"
        return 1
    fi
    
    # 调用Python辅助脚本
    gs_log_debug "调用Python操作: $operation ${args[*]}"
    $_GS_PYTHON_CMD "$helper_script" "$operation" "${args[@]}"
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        gs_log_debug "Python操作失败: $operation (退出码: $exit_code)"
    fi
    
    return $exit_code
}

# 获取Python信息
gs_python_info() {
    if [[ "$_GS_PYTHON_AVAILABLE" == "true" ]]; then
        printf "Python命令: %s\n" "$_GS_PYTHON_CMD"
        printf "Python版本: %s\n" "$_GS_PYTHON_VERSION"
        printf "状态: 可用\n"
        
        # 显示Python详细版本
        local full_version
        full_version=$($_GS_PYTHON_CMD --version 2>&1)
        printf "完整版本: %s\n" "$full_version"
    else
        printf "Python状态: 不可用\n"
        if [[ -n "$_GS_PYTHON_CMD" ]]; then
            printf "检测到命令: %s\n" "$_GS_PYTHON_CMD"
        else
            printf "未检测到Python环境\n"
        fi
    fi
}

# 检查Python是否可用
gs_python_available() {
    [[ "$_GS_PYTHON_AVAILABLE" == "true" ]]
}

# 初始化Python环境（在模块加载时自动调用）
if [[ -z "$_GS_PYTHON_CMD" ]]; then
    gs_python_detect
fi

# 导出全局变量
export _GS_PYTHON_CMD _GS_PYTHON_VERSION _GS_PYTHON_AVAILABLE