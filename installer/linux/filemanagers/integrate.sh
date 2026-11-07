#!/bin/sh
# Per-user file manager entries that cannot be installed system-wide (Nautilus scripts, Thunar
# custom actions). Run as the user, never as root. Nothing is downloaded; only files from
# /usr/share/shield are copied. Remove: delete the two entries again.
set -eu
[ "$(id -u)" -ne 0 ] || { echo "run this as your own user, not as root" >&2; exit 1; }
src=/usr/share/shield
umask 077
d="${XDG_DATA_HOME:-$HOME/.local/share}/nautilus/scripts"
mkdir -p "$d"
install -m 0700 "$src/nautilus-encrypt.sh" "$d/Encrypt with Shield"
uca="${XDG_CONFIG_HOME:-$HOME/.config}/Thunar/uca.xml"
if [ -f "$uca" ] && ! grep -q shield-encrypt-3 "$uca"; then
    tmp="$uca.shield.$$"
    awk -v f="$src/thunar-uca.xml" '/<\/actions>/ { while ((getline l < f) > 0) if (l !~ /^<!--|^     or run/) print l } { print }' "$uca" > "$tmp"
    mv "$tmp" "$uca"
fi
echo "Shield: Nautilus script and Thunar action installed for $(id -un)."
