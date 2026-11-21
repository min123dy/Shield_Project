#!/bin/sh
# Per-user file manager entries that cannot be installed system-wide (Nautilus scripts, Thunar
# custom actions). Run as the user, never as root. Nothing is downloaded; only files from
# /usr/share/shield are copied. Remove: delete the entries again.
set -eu
[ "$(id -u)" -ne 0 ] || { echo "run this as your own user, not as root" >&2; exit 1; }
src=/usr/share/shield
umask 077
d="${XDG_DATA_HOME:-$HOME/.local/share}/nautilus/scripts"
mkdir -p "$d"
install -m 0700 "$src/nautilus-encrypt.sh" "$d/Encrypt with Shield"
install -m 0700 "$src/nautilus-open.sh" "$d/Open in SHIELD"
install -m 0700 "$src/nautilus-wipe.sh" "$d/Secure delete with SHIELD"
uca="${XDG_CONFIG_HOME:-$HOME/.config}/Thunar/uca.xml"
if [ -f "$uca" ]; then
    # each <action> of thunar-uca.xml whose unique-id is not in uca.xml yet goes before </actions>
    tmp="$uca.shield.$$"
    awk -v f="$src/thunar-uca.xml" '
        BEGIN {
            while ((getline l < f) > 0) {
                if (l ~ /^<!--|^     or run/) continue
                blk = blk l "\n"
                if (l ~ /<unique-id>/) { id = l; sub(/.*<unique-id>/, "", id); sub(/<\/unique-id>.*/, "", id) }
                if (l ~ /<\/action>/) { n++; body[n] = blk; ids[n] = id; blk = "" }
            }
        }
        { seen = seen $0 "\n" }
        /<\/actions>/ && !done { for (i = 1; i <= n; i++) if (index(seen, "<unique-id>" ids[i] "</unique-id>") == 0) printf "%s", body[i]; done = 1 }
        { print }
    ' "$uca" > "$tmp"
    mv "$tmp" "$uca"
fi
echo "Shield: Nautilus scripts and Thunar actions installed for $(id -un)."
