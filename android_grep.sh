function gs_aosp_help() {
cat <<EOF
- gs_aosp_cgrep:      Greps on all local C/C++ files.
- gs_aosp_ggrep:      Greps on all local Gradle files.
- gs_aosp_gogrep:     Greps on all local Go files.
- gs_aosp_jgrep:      Greps on all local Java files.
- gs_aosp_ktgrep:     Greps on all local Kotlin files.
- gs_aosp_resgrep:    Greps on all local res/*.xml files.
- gs_aosp_mangrep:    Greps on all local AndroidManifest.xml files.
- gs_aosp_mgrep:      Greps on all local Makefiles and *.bp files.
- gs_aosp_owngrep:    Greps on all local OWNERS files.
- gs_aosp_rsgrep:     Greps on all local Rust files.
- gs_aosp_sepgrep:    Greps on all local sepolicy files.
- gs_aosp_sgrep:      Greps on all local source files.
EOF
}

# global aosp grep
case `uname -s` in
    Darwin)
        function gs_aosp_sgrep() {
            find -E . -name .repo -prune -o -name .git -prune -o  -type f -iregex '.*\.(c|h|cc|cpp|hpp|S|java|kt|xml|sh|mk|aidl|vts|proto)' \
                -exec grep --color -n "$@" {} +
        }

        ;;
    *)
        function gs_aosp_sgrep() {
            find . -name .repo -prune -o -name .git -prune -o  -type f -iregex '.*\.\(c\|h\|cc\|cpp\|hpp\|S\|java\|kt\|xml\|sh\|mk\|aidl\|vts\|proto\)' \
                -exec grep --color -n "$@" {} +
        }
        ;;
esac

function gs_aosp_ggrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.gradle" \
        -exec grep --color -n "$@" {} +
}

function gs_aosp_gogrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.go" \
        -exec grep --color -n "$@" {} +
}

function gs_aosp_jgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.java" \
        -exec grep --color -n "$@" {} +
}

function gs_aosp_rsgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.rs" \
        -exec grep --color -n "$@" {} +
}

function gs_aosp_ktgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.kt" \
        -exec grep --color -n "$@" {} +
}

function gs_aosp_cgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) \
        -exec grep --color -n "$@" {} +
}

function gs_aosp_resgrep() {
    local dir
    for dir in `find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name res -type d`; do
        find $dir -type f -name '*\.xml' -exec grep --color -n "$@" {} +
    done
}

function gs_aosp_mangrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -type f -name 'AndroidManifest.xml' \
        -exec grep --color -n "$@" {} +
}

function gs_aosp_owngrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -type f -name 'OWNERS' \
        -exec grep --color -n "$@" {} +
}

function gs_aosp_sepgrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -name sepolicy -type d \
        -exec grep --color -n -r --exclude-dir=\.git "$@" {} +
}

function gs_aosp_rcgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.rc*" \
        -exec grep --color -n "$@" {} +
}

case `uname -s` in
    Darwin)
        function gs_aosp_mgrep() {
            find -E . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o \( -iregex '.*/(Makefile|Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color -n "$@" {} +
        }

        function gs_aosp_treegrep() {
            find -E . -name .repo -prune -o -name .git -prune -o -type f -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml)' \
                -exec grep --color -n -i "$@" {} +
        }

        ;;
    *)
        function gs_aosp_mgrep() {
            find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o \( -regextype posix-egrep -iregex '(.*\/Makefile|.*\/Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regextype posix-extended -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color -n "$@" {} +
        }

        function gs_aosp_treegrep() {
            find . -name .repo -prune -o -name .git -prune -o -regextype posix-egrep -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml)' -type f \
                -exec grep --color -n -i "$@" {} +
        }

        ;;
esac