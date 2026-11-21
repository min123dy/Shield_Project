#!/bin/sh
# 3.1.0 final, review F: runs the three Nautilus scripts with a stub shield-gui and checks the
# arguments it receives byte for byte. Run on Linux (any POSIX sh; also with dash):
#   sh installer/linux/tests/nautilus_scripts_test.sh
# The real Nautilus is not involved (not verified on a real desktop, see docs/05).
set -u
here=$(cd "$(dirname "$0")" && pwd)
fm=$here/../filemanagers
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/view" "$t/elsewhere"
# the stub prints every argument as one line of hex, so names with newlines compare exactly
cat > "$t/bin/shield-gui" <<'EOF'
#!/bin/sh
for a do printf '%s' "$a" | od -An -tx1 | tr -d ' \n'; echo; done > "$SHIELD_TEST_OUT"
EOF
chmod +x "$t/bin/shield-gui"
hex() { for a do printf '%s' "$a" | od -An -tx1 | tr -d ' \n'; echo; done; }
us=$(printf '\037') # separates the items of one list below (no test name contains it)
nl="
"
fails=0
pass=0
# check <title> <script> <cwd> <env list or "-" for unset> <args, US-separated> <expected argv, US-separated>
check() {
    title=$1 script=$2 cwd=$3 envl=$4 args=$5 expect=$6
    oldifs=$IFS
    IFS=$us
    set -f
    # shellcheck disable=SC2086
    want=$(hex $expect)
    : > "$t/out"
    (
        cd "$cwd" || exit 1
        if [ "$envl" = "-" ]; then
            unset NAUTILUS_SCRIPT_SELECTED_FILE_PATHS
        else
            NAUTILUS_SCRIPT_SELECTED_FILE_PATHS=$envl
            export NAUTILUS_SCRIPT_SELECTED_FILE_PATHS
        fi
        # shellcheck disable=SC2086
        set -- $args
        IFS=$oldifs
        set +f
        PATH=$t/bin:$PATH SHIELD_TEST_OUT=$t/out sh "$fm/$script" "$@"
    )
    IFS=$oldifs
    set +f
    got=$(cat "$t/out")
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
        echo "ok   $title"
    else
        fails=$((fails + 1))
        echo "FAIL $title"
        echo "  want: $want"
        echo "  got:  $got"
    fi
}
v=$t/view
e=$t/elsewhere
for nm in "a b.txt" "say 'hi'.txt" "say \"hi\".txt" "\$(touch pwned).txt" "\`touch pwned\`" "-rf" "--yes" "*.txt" "back\\slash" " lead and trail " "tab	in"; do
    check "no list, relative: [$nm]" nautilus-wipe.sh "$v" - "$nm" "--wipe$us--$us$v/$nm"
    check "list lines up: [$nm]" nautilus-wipe.sh "$v" "$e/$nm$nl" "$nm" "--wipe$us--$us$e/$nm"
    check "encrypt, no list: [$nm]" nautilus-encrypt.sh "$v" - "$nm" "--encrypt-multi$us--$us$v/$nm"
done
check "two items from a search view use the list" nautilus-encrypt.sh "$v" "$e/x.txt$nl$t/y z.txt$nl" "x.txt${us}y z.txt" "--encrypt-multi$us--$us$e/x.txt$us$t/y z.txt"
check "list without trailing newline" nautilus-wipe.sh "$v" "$e/x.txt" "x.txt" "--wipe$us--$us$e/x.txt"
check "newline in a name: the list is ambiguous, arguments are used" nautilus-wipe.sh "$v" "$e/new${nl}line.txt$nl" "new${nl}line.txt" "--wipe$us--$us$v/new${nl}line.txt"
check "newline name next to a plain one" nautilus-wipe.sh "$v" "$e/a$nl$e/b${nl}c$nl" "a${us}b${nl}c" "--wipe$us--$us$v/a$us$v/b${nl}c"
check "list names other items: arguments are used" nautilus-wipe.sh "$v" "$e/other.txt$nl" "mine.txt" "--wipe$us--$us$v/mine.txt"
check "list with fewer lines than arguments" nautilus-wipe.sh "$v" "$e/a$nl" "a${us}b" "--wipe$us--$us$v/a$us$v/b"
check "list with more lines than arguments" nautilus-wipe.sh "$v" "$e/a$nl$e/b$nl" "a" "--wipe$us--$us$v/a"
check "relative line in the list is not trusted" nautilus-wipe.sh "$v" "a$nl" "a" "--wipe$us--$us$v/a"
check "list line only sharing a suffix is not used" nautilus-wipe.sh "$v" "$e/xa$nl" "a" "--wipe$us--$us$v/a"
check "absolute argument stays" nautilus-wipe.sh "$v" - "$e/abs.txt" "--wipe$us--$us$e/abs.txt"
check "file:// argument is passed on for Shield to decode" nautilus-wipe.sh "$v" - "file:///home/u/My%20File.txt" "--wipe$us--${us}file:///home/u/My%20File.txt"
check "open takes the first item" nautilus-open.sh "$v" "$e/c.shd$nl$e/d$nl" "c.shd${us}d" "--open$us--$us$e/c.shd"
check "open, relative, no list" nautilus-open.sh "$v" - "my box" "--open$us--$us$v/my box"
# no selection: the stub is not started; no name was ever run as a command
: > "$t/out"
(cd "$v" && PATH=$t/bin:$PATH SHIELD_TEST_OUT=$t/out sh "$fm/nautilus-wipe.sh")
if [ -s "$t/out" ] || [ -e "$v/pwned" ] || [ -e "$e/pwned" ] || [ -e "$here/pwned" ]; then
    fails=$((fails + 1))
    echo "FAIL nothing selected / nothing run"
else
    pass=$((pass + 1))
    echo "ok   nothing selected: Shield is not started, no name was run"
fi
echo "nautilus scripts: $pass passed, $fails failed"
[ "$fails" -eq 0 ]
