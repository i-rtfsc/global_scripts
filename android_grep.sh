# global aosp grep
case `uname -s` in
    Darwin)
        function sgrep() {
            find -E . -name .repo -prune -o -name .git -prune -o  -type f -iregex '.*\.(c|h|cc|cpp|hpp|S|java|kt|xml|sh|mk|aidl|vts|proto)' \
                -exec grep --color -n "$@" {} +
        }

        ;;
    *)
        function sgrep() {
            find . -name .repo -prune -o -name .git -prune -o  -type f -iregex '.*\.\(c\|h\|cc\|cpp\|hpp\|S\|java\|kt\|xml\|sh\|mk\|aidl\|vts\|proto\)' \
                -exec grep --color -n "$@" {} +
        }
        ;;
esac

function ggrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.gradle" \
        -exec grep --color -n "$@" {} +
}

function gogrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.go" \
        -exec grep --color -n "$@" {} +
}

function jgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.java" \
        -exec grep --color -n "$@" {} +
}

function rsgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.rs" \
        -exec grep --color -n "$@" {} +
}

function ktgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.kt" \
        -exec grep --color -n "$@" {} +
}

function cgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) \
        -exec grep --color -n "$@" {} +
}

function resgrep() {
    local dir
    for dir in `find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name res -type d`; do
        find $dir -type f -name '*\.xml' -exec grep --color -n "$@" {} +
    done
}

function mangrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -type f -name 'AndroidManifest.xml' \
        -exec grep --color -n "$@" {} +
}

function owngrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -type f -name 'OWNERS' \
        -exec grep --color -n "$@" {} +
}

function sepgrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -name sepolicy -type d \
        -exec grep --color -n -r --exclude-dir=\.git "$@" {} +
}

function rcgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.rc*" \
        -exec grep --color -n "$@" {} +
}

case `uname -s` in
    Darwin)
        function mgrep() {
            find -E . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o \( -iregex '.*/(Makefile|Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color -n "$@" {} +
        }

        function treegrep() {
            find -E . -name .repo -prune -o -name .git -prune -o -type f -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml)' \
                -exec grep --color -n -i "$@" {} +
        }

        ;;
    *)
        function mgrep() {
            find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o \( -regextype posix-egrep -iregex '(.*\/Makefile|.*\/Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regextype posix-extended -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color -n "$@" {} +
        }

        function treegrep() {
            find . -name .repo -prune -o -name .git -prune -o -regextype posix-egrep -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml)' -type f \
                -exec grep --color -n -i "$@" {} +
        }

        ;;
esac