#!/usr/bin/env fish
# Global Scripts Router - Shell/JSON Command Dispatcher (Fish Shell)
# Handles shell and json type commands outside Python environment

function gs-router --description "Global Scripts command router for shell/json commands"
    # Default router index path
    set -l ROUTER_INDEX "$GS_CACHE_DIR/router.json"
    if test -z "$GS_CACHE_DIR"
        set ROUTER_INDEX "$HOME/.config/global-scripts/cache/router.json"
    end

    # Check if jq is available
    if not command -v jq >/dev/null 2>&1
        echo "Error: jq is required for command routing" >&2
        echo "Please install jq: brew install jq (macOS) or apt install jq (Linux)" >&2
        return 1
    end

    # Check if router index exists
    if not test -f "$ROUTER_INDEX"
        echo "Error: Router index not found at $ROUTER_INDEX" >&2
        echo "Please run: gs refresh" >&2
        return 1
    end


    set -l plugin $argv[1]
    set -e argv[1]  # Remove first element

    if test -z "$plugin"
        echo "Usage: gs-router <plugin> [subplugin] <command> [args...]" >&2
        return 1
    end


    # Build query based on arguments
    set -l query ""
    set -l args

    if test (count $argv) -eq 0
        # Single argument: gs-router <plugin>
        set query $plugin
    else if test (count $argv) -eq 1
        # Two arguments: gs-router <plugin> <command>
        set query $argv[1]
        set -e argv[1]
        set args $argv
    else
        # Three or more: gs-router <plugin> <subplugin> <command> [args...]
        # Try two-token form first: "subplugin command"
        set -l two_token "$argv[1] $argv[2]"
        set -l single_token $argv[2]


        # Check if two-token form exists
        set -l has_two_token (jq -r --arg plugin "$plugin" --arg query "$two_token" \
            ".plugins[\$plugin].commands[\$query] // empty" "$ROUTER_INDEX" 2>/dev/null)


        if test -n "$has_two_token"
            set query "$two_token"
            set -e argv[1..2]
            set args $argv
        else
            set query $single_token
            set -e argv[1..2]
            set args $argv
        end
    end

    # Query router index for command metadata
    set -l meta (jq -c --arg plugin "$plugin" --arg query "$query" \
        ".plugins[\$plugin].commands[\$query] // empty" "$ROUTER_INDEX" 2>/dev/null)


    if test -z "$meta"; or test "$meta" = "null"
        echo "Error: Command not found in router index: $plugin $query" >&2
        return 1
    end

    # Extract metadata
    set -l kind (echo "$meta" | jq -r '.kind // empty')
    set -l entry (echo "$meta" | jq -r '.entry // empty')
    set -l func (echo "$meta" | jq -r '.name // empty')
    set -l command_tpl (echo "$meta" | jq -r '.command // empty')


    switch "$kind"
        case shell

            # Shell script execution
            if test -z "$entry"; or not test -f "$entry"
                # Try relative to GS_ROOT
                set entry "$GS_ROOT/$entry"
            end

            if not test -f "$entry"
                echo "Error: Shell script not found: $entry" >&2
                return 1
            end


            # For fish, we need to source the script and call the function
            # Fish functions are defined differently than bash functions
            # We'll need to execute the shell script with bash if it's a .sh file

            if string match -q "*.sh" "$entry"
                # It's a bash script, we need to source it and execute in current shell
                # to preserve environment variables
                set -l sub (echo "$meta" | jq -r '.subplugin // empty')
                # Replace hyphens with underscores for bash compatibility
                set -l func_normalized (string replace -a '-' '_' $func)
                set -l full_func_name
                if test -n "$sub"
                    set full_func_name "gs_"$plugin"_"$sub"_"$func_normalized
                else
                    set full_func_name "gs_"$plugin"_"$func_normalized
                end

                # Create a temporary script that exports env vars to a temp file
                set -l tmp_env (mktemp)
                set -l tmp_script (mktemp)

                # Build the script that will export variables
                echo "#!/bin/bash" > $tmp_script
                echo "source '$entry'" >> $tmp_script
                echo "$full_func_name $args" >> $tmp_script
                echo "env > '$tmp_env'" >> $tmp_script

                # Execute the script
                bash $tmp_script
                set -l exit_code $status

                # Import environment variables that were exported
                if test -f "$tmp_env"
                    for line in (cat $tmp_env)
                        # Parse VAR=value format
                        if string match -qr '^([A-Z_][A-Z0-9_]*)=(.*)$' $line
                            set -l var_name (string replace -r '^([A-Z_][A-Z0-9_]*)=.*$' '$1' $line)
                            set -l var_value (string replace -r '^[A-Z_][A-Z0-9_]*=(.*)$' '$1' $line)
                            # Only import specific variables we care about
                            if string match -qr '^(ANTHROPIC_|AGENT_ROUTER_|OPENAI_|GEMINI_)' $var_name
                                set -gx $var_name $var_value
                            end
                        end
                    end
                end

                # Cleanup
                rm -f $tmp_script $tmp_env

                return $exit_code
            else if string match -q "*.fish" "$entry"
                # It's a fish script, source and call
                source "$entry"

                # Build full function name
                set -l sub (echo "$meta" | jq -r '.subplugin // empty')
                # Replace hyphens with underscores for function name compatibility
                set -l func_normalized (string replace -a '-' '_' $func)
                set -l full_func_name
                if test -n "$sub"
                    set full_func_name "gs_"$plugin"_"$sub"_"$func_normalized
                else
                    set full_func_name "gs_"$plugin"_"$func_normalized
                end

                if not functions -q $full_func_name
                    echo "Error: Function '$full_func_name' not found in $entry" >&2
                    return 1
                end

                $full_func_name $args
            else
                echo "Error: Unknown script type: $entry" >&2
                return 1
            end

        case json
            # JSON command execution
            if test -z "$command_tpl"
                echo "Error: No command template defined for json type" >&2
                return 1
            end

            # Replace {args} placeholder if present
            set -l cmd $command_tpl
            if string match -q "*{args}*" "$cmd"
                set cmd (string replace -a "{args}" "$args" "$cmd")
            else if test (count $args) -gt 0
                set cmd "$cmd $args"
            end

            # Change to config file directory if entry is provided
            set -l exec_dir $PWD
            if test -n "$entry"; and test -f "$entry"
                set exec_dir (dirname "$entry")
            else if test -n "$entry"
                set exec_dir "$GS_ROOT/"(dirname "$entry")
            end

            # Execute command
            pushd "$exec_dir" >/dev/null
            eval $cmd
            set -l exit_code $status
            popd >/dev/null
            return $exit_code

        case '*'
            echo "Error: Unknown command kind: $kind" >&2
            return 1
    end
end

# Note: This script only defines the gs-router function.
# It should be sourced, not executed directly.
