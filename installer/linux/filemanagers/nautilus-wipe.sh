#!/bin/sh
# Nautilus script "Secure delete with SHIELD": opens the Shield window with the selected items.
# Nothing is deleted here: the window scans the items, refuses protected paths and asks three
# confirmations first.
[ $# -ge 1 ] || exit 0
# Selection as absolute paths (3.1.0 final, review F). Nautilus passes the selected names as
# arguments relative to the folder it runs the script in (search and "Recent" views show items
# from elsewhere) and lists full paths, newline-separated, in $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS.
# That list is used when it lines up with the arguments one to one (each line absolute and equal
# to, or ending in "/" plus, its argument); a name containing a newline makes the list ambiguous,
# and then every argument is used as given, made absolute against $PWD. Shield normalizes and
# checks the items again (spool::normalize_arg); nothing here is evaluated or run.
nl="
"
n=$#
r=${NAUTILUS_SCRIPT_SELECTED_FILE_PATHS-}
ok=0
if [ -n "$r" ]; then
    ok=1
    for a do
        case $r in
            *"$nl"*) l=${r%%"$nl"*}; r=${r#*"$nl"} ;;
            *) l=$r; r= ;;
        esac
        case $l in /*) ;; *) ok=0; break ;; esac
        case $l in "$a" | */"$a") ;; *) ok=0; break ;; esac
    done
    [ -z "$r" ] || ok=0
fi
r=${NAUTILUS_SCRIPT_SELECTED_FILE_PATHS-}
i=0
while [ "$i" -lt "$n" ]; do
    a=$1
    shift
    if [ "$ok" = 1 ]; then
        case $r in
            *"$nl"*) a=${r%%"$nl"*}; r=${r#*"$nl"} ;;
            *) a=$r; r= ;;
        esac
    else
        case $a in /* | file://*) ;; *) a=$PWD/$a ;; esac
    fi
    set -- "$@" "$a"
    i=$((i + 1))
done
exec shield-gui --wipe -- "$@"
