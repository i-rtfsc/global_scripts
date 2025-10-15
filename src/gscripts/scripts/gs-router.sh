#!/usr/bin/env bash
# Global Scripts Router - Shell/JSON Command Dispatcher
# Handles shell and json type commands outside Python environment

# Default router index path
ROUTER_INDEX="${GS_CACHE_DIR:-$HOME/.config/global-scripts/cache}/router.json"

gs-router() {
    local plugin="$1"
    shift

    if [[ -z "$plugin" ]]; then
        echo "Usage: gs-router <plugin> [subplugin] <command> [args...]" >&2
        return 1
    fi

    # Check if jq is available
    if ! command -v jq &>/dev/null; then
        echo "Error: jq is required for command routing" >&2
        echo "Please install jq: brew install jq (macOS) or apt install jq (Linux)" >&2
        return 1
    fi

    # Check if router index exists
    if [[ ! -f "$ROUTER_INDEX" ]]; then
        echo "Error: Router index not found at $ROUTER_INDEX" >&2
        echo "Please run: gs refresh" >&2
        return 1
    fi

    # Build query based on arguments
    local query=""
    local args=()

    if [[ $# -eq 0 ]]; then
        # Single argument: gs-router <plugin>
        query="$plugin"
    elif [[ $# -eq 1 ]]; then
        # Two arguments: gs-router <plugin> <command>
        query="$1"
        shift
        args=("$@")
    else
        # Three or more: gs-router <plugin> <subplugin> <command> [args...]
        # Try two-token form first: "subplugin command"
        local two_token="$1 $2"
        local single_token="$2"

        # Check if two-token form exists
        local has_two_token=$(jq -r --arg plugin "$plugin" --arg query "$two_token" \
            '.plugins[$plugin].commands[$query] // empty' "$ROUTER_INDEX" 2>/dev/null)

        if [[ -n "$has_two_token" ]]; then
            query="$two_token"
            shift 2
            args=("$@")
        else
            query="$single_token"
            shift 2
            args=("$@")
        fi
    fi

    # Query router index for command metadata
    local meta=$(jq -c --arg plugin "$plugin" --arg query "$query" \
        '.plugins[$plugin].commands[$query] // empty' "$ROUTER_INDEX" 2>/dev/null)

    if [[ -z "$meta" ]] || [[ "$meta" == "null" ]]; then
        echo "Error: Command not found in router index: $plugin $query" >&2
        return 1
    fi

    # Extract metadata
    local kind=$(echo "$meta" | jq -r '.kind // empty')
    local entry=$(echo "$meta" | jq -r '.entry // empty')
    local func=$(echo "$meta" | jq -r '.name // empty')
    local command_tpl=$(echo "$meta" | jq -r '.command // empty')

    case "$kind" in
        shell)
            # Shell script execution
            if [[ -z "$entry" ]] || [[ ! -f "$entry" ]]; then
                # Try relative to GS_ROOT
                entry="${GS_ROOT}/${entry}"
            fi

            if [[ ! -f "$entry" ]]; then
                echo "Error: Shell script not found: $entry" >&2
                return 1
            fi

            # Source the script
            source "$entry"

            # Build full function name based on plugin structure
            # For subplugin commands: gs_<plugin>_<subplugin>_<func>
            # For direct commands: gs_<plugin>_<func>
            # Note: Replace hyphens with underscores for bash compatibility
            local sub=$(echo "$meta" | jq -r '.subplugin // empty')
            local func_normalized=$(echo "$func" | tr '-' '_')
            local full_func_name
            if [[ -n "$sub" ]]; then
                full_func_name="gs_${plugin}_${sub}_${func_normalized}"
            else
                full_func_name="gs_${plugin}_${func_normalized}"
            fi

            if ! declare -F "$full_func_name" &>/dev/null; then
                echo "Error: Function '$full_func_name' not found in $entry" >&2
                return 1
            fi

            "$full_func_name" "${args[@]}"
            ;;

        json)
            # JSON command execution
            if [[ -z "$command_tpl" ]]; then
                echo "Error: No command template defined for json type" >&2
                return 1
            fi

            # Replace {args} placeholder if present
            local cmd="$command_tpl"
            if [[ "$cmd" == *"{args}"* ]]; then
                cmd="${cmd//\{args\}/${args[*]}}"
            elif [[ ${#args[@]} -gt 0 ]]; then
                cmd="$cmd ${args[*]}"
            fi

            # Change to config file directory if entry is provided
            local exec_dir="$PWD"
            if [[ -n "$entry" ]] && [[ -f "$entry" ]]; then
                exec_dir=$(dirname "$entry")
            elif [[ -n "$entry" ]]; then
                exec_dir="${GS_ROOT}/$(dirname "$entry")"
            fi

            # Execute command
            (cd "$exec_dir" && eval "$cmd")
            ;;

        *)
            echo "Error: Unknown command kind: $kind" >&2
            return 1
            ;;
    esac
}

# If script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs-router "$@"
fi