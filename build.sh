#!/usr/bin/env bash
# Shield 3.0 Linux build: tests, shield + shield-gui, .deb, AppImage, optional .rpm, static
# console binary, source zip, signed release manifest, optional OpenPGP signatures, SHA256SUMS.
#
# Inputs (option, environment variable, or asked on a terminal):
#   --repo https://github.com/<owner>/<repo>   SHIELD_REPO_URL   (empty: no link, no updates)
#   --pubkey key.asc                           SHIELD_PUBKEY_PATH (default keys/release_key.asc)
#   --sign | --no-sign                         SHIELD_SIGN=y|n
#   --variants deb,appimage,console,rpm,zip    SHIELD_VARIANTS   (default deb,appimage,console,zip)
#   --zig            build the static console binary with cargo-zigbuild (also for aarch64)
#   --arch x86_64|aarch64   console target (default: this machine; deb/AppImage: always native)
#   --merge-manifest <file>   add the lines of another manifest (e.g. the Windows packages)
#   --gpg-home <dir>  --skip-tests
# Secrets: the passphrase is asked by gpg-agent / pinentry, never passed or printed. CI imports
# the key from an encrypted secret into a throwaway GNUPGHOME (docs 02); never commit it.
set -euo pipefail
set +x
umask 022
cd "$(dirname "$0")"
ROOT=$(pwd)

repo=${SHIELD_REPO_URL:-}; pubkey=${SHIELD_PUBKEY_PATH:-}; sign=${SHIELD_SIGN:-}
variants=${SHIELD_VARIANTS:-deb,appimage,console,zip}
zig=0; arch=$(uname -m); merge=""; gpghome=""; skip_tests=0
while [ $# -gt 0 ]; do
    case "$1" in
        --repo) repo=$2; shift 2 ;;
        --pubkey) pubkey=$2; shift 2 ;;
        --sign) sign=y; shift ;;
        --no-sign) sign=n; shift ;;
        --variants) variants=$2; shift 2 ;;
        --zig) zig=1; shift ;;
        --arch) arch=$2; shift 2 ;;
        --merge-manifest) merge=$2; shift 2 ;;
        --gpg-home) gpghome=$2; shift 2 ;;
        --skip-tests) skip_tests=1; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
die() { echo "error: $*" >&2; exit 1; }
step() { printf '\033[36m== %s\033[0m\n' "$*"; }
ask() { local a; read -r -p "$1 (y/N) " a; [[ "$a" =~ ^[[:space:]]*(y|yes|예|네|ㅇ)[[:space:]]*$ ]]; }
tty=0; [ -t 0 ] && tty=1

# ------------------------------------------------------------------ 0. inputs
if [ -z "$repo" ] && [ $tty = 1 ]; then read -r -p "GitHub repository URL (https://github.com/<owner>/<repo>, Enter = none): " repo; fi
repo=$(printf '%s' "$repo" | tr -d '[:space:]')
if [ -n "$repo" ] && ! [[ "$repo" =~ ^https://github\.com/[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}/?$ ]]; then
    die "repository URL must be https://github.com/<owner>/<repo>: $repo"
fi
[ -n "$pubkey" ] || pubkey="$ROOT/keys/release_key.asc"
[ -f "$pubkey" ] || die "public key not found: $pubkey (needed for update / integrity checks)"
pubkey=$(cd "$(dirname "$pubkey")" && pwd)/$(basename "$pubkey")
grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "$pubkey" || die "not an armored OpenPGP public key: $pubkey"
! grep -qE 'PRIVATE KEY BLOCK|SECRET KEY' "$pubkey" || die "this file contains a private key; give the public key only"
if [ -z "$sign" ]; then if [ $tty = 1 ] && ask "Sign with GPG? / GPG 서명을 하시겠습니까?"; then sign=y; else sign=n; fi; fi
case "$sign" in y|yes|1|true) sign=y ;; *) sign=n ;; esac
IFS=', ' read -r -a want <<< "$variants"
has() { local v; for v in "${want[@]}"; do [ "$v" = "$1" ] && return 0; done; return 1; }
for v in "${want[@]}"; do case "$v" in deb|appimage|console|rpm|zip) ;; *) die "unknown variant: $v" ;; esac; done
case "$arch" in x86_64|amd64) arch=x86_64; deb_arch=amd64; short=x64 ;; aarch64|arm64) arch=aarch64; deb_arch=arm64; short=arm64 ;; *) die "unsupported arch: $arch" ;; esac
native=$(uname -m); [ "$native" = arm64 ] && native=aarch64
version=$(sed -n 's/^version = "\([0-9]*\.[0-9]*\.[0-9]*\)"/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || die "no version in Cargo.toml"
vu=${version//./_}

tmphome=""; fpr=""
cleanup() { [ -n "$tmphome" ] && { gpgconf --homedir "$tmphome" --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$tmphome"; }; }
trap cleanup EXIT
gpg_user() { if [ -n "$gpghome" ]; then gpg --homedir "$gpghome" "$@"; else gpg "$@"; fi; }
if [ $sign = y ]; then
    command -v gpg >/dev/null || die "gpg not found (install gnupg or use --no-sign)"
    tmphome=$(mktemp -d); chmod 700 "$tmphome"
    gpg --homedir "$tmphome" --batch --quiet --import "$pubkey" 2>/dev/null
    [ "$(gpg --homedir "$tmphome" --batch --with-colons --list-keys | grep -c '^pub:')" = 1 ] || die "the key file must hold exactly one key"
    fpr=$(gpg --homedir "$tmphome" --batch --with-colons --fingerprint | awk -F: '/^fpr:/ {print $10; exit}')
    [[ "$fpr" =~ ^[0-9A-F]{40}([0-9A-F]{24})?$ ]] || die "cannot read the fingerprint"
    echo "signing key fingerprint: $fpr"
    gpg_user --batch --with-colons --list-secret-keys "$fpr" 2>/dev/null | grep -q '^sec:' || die "no secret key for $fpr in the local keyring"
fi
sign_file() {
    rm -f "$1.sig"
    gpg_user --local-user "$fpr" --digest-algo SHA512 --detach-sign --output "$1.sig" "$1"
    gpg --homedir "$tmphome" --batch --status-fd 1 --verify "$1.sig" "$1" 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG .*$fpr" \
        || { rm -f "$1.sig"; die "signature check failed: $1.sig"; }
    echo "  signed: $(basename "$1").sig"
}
echo "Shield v$version · repo: ${repo:-(none)} · sign: $sign · variants: ${want[*]} · console arch: $arch"

# ------------------------------------------------------------------ 1. tests and builds
export SHIELD_REPO_URL="$repo" SHIELD_PUBKEY_PATH="$pubkey"
if [ $skip_tests = 0 ]; then step "tests"; cargo test --workspace --release; fi
target=${CARGO_TARGET_DIR:-$ROOT/target}
if has deb || has appimage || has rpm; then
    step "release build: shield, shield-gui ($native)"
    cargo build --release -p shield-gui -p shield-cli
    cargo run -q --release -p shield-gui --example export_icon -- "$target/icons"
fi
dist="$ROOT/dist"
# earlier release files are kept: moved aside, never deleted
if [ -d "$dist" ] && [ -n "$(ls -A "$dist")" ]; then
    old="$ROOT/dist_old_$(date +%Y%m%d_%H%M%S)"; mv "$dist" "$old"; echo "previous dist moved to ${old##*/}"
fi
mkdir -p "$dist"
packages=()
if has console; then
    step "static console binary ($arch-unknown-linux-musl, no GUI dependencies)"
    t="$arch-unknown-linux-musl"
    if [ $zig = 1 ]; then cargo zigbuild --release -p shield-cli --no-default-features --target "$t"
    else cargo build --release -p shield-cli --no-default-features --target "$t"; fi
    out="$dist/shield-console_v${version}_linux_${short}"
    install -m 0755 "$target/$t/release/shield" "$out"
    packages+=("$out")
fi

# ------------------------------------------------------------------ 2. package tree
stage="$target/pkgroot"
if has deb || has appimage || has rpm; then
    step "package tree"
    rm -rf "$stage"; mkdir -p "$stage"
    L=installer/linux
    install -Dm0755 "$target/release/shield" "$stage/usr/bin/shield"
    install -Dm0755 "$target/release/shield-gui" "$stage/usr/bin/shield-gui"
    if [ $sign = y ]; then
        # next to the programs for the built-in integrity check
        sign_file "$stage/usr/bin/shield"; sign_file "$stage/usr/bin/shield-gui"
        chmod 0644 "$stage/usr/bin/"*.sig
    fi
    install -Dm0644 $L/shield.desktop "$stage/usr/share/applications/shield.desktop"
    install -Dm0644 $L/shield-open.desktop "$stage/usr/share/applications/shield-open.desktop"
    install -Dm0644 $L/shield-mime.xml "$stage/usr/share/mime/packages/shield.xml"
    for s in 16 32 48 64 128 256; do install -Dm0644 "$target/icons/${s}x${s}/apps/shield.png" "$stage/usr/share/icons/hicolor/${s}x${s}/apps/shield.png"; done
    install -Dm0644 $L/filemanagers/shield-encrypt.nemo_action "$stage/usr/share/nemo/actions/shield-encrypt.nemo_action"
    install -Dm0644 $L/filemanagers/shield-decrypt.nemo_action "$stage/usr/share/nemo/actions/shield-decrypt.nemo_action"
    install -Dm0644 $L/filemanagers/shield-dolphin.desktop "$stage/usr/share/kio/servicemenus/shield.desktop"
    install -Dm0644 $L/filemanagers/shield-dolphin.desktop "$stage/usr/share/kservices5/ServiceMenus/shield.desktop"
    install -Dm0755 $L/filemanagers/integrate.sh "$stage/usr/share/shield/integrate.sh"
    install -Dm0755 $L/filemanagers/nautilus-encrypt.sh "$stage/usr/share/shield/nautilus-encrypt.sh"
    install -Dm0644 $L/filemanagers/thunar-uca.xml "$stage/usr/share/shield/thunar-uca.xml"
    install -Dm0644 LICENSE "$stage/usr/share/doc/shield/copyright"
    install -Dm0644 docs/en/03_usage.txt "$stage/usr/share/doc/shield/usage.txt"
    install -Dm0644 "docs/03_사용_방법.txt" "$stage/usr/share/doc/shield/usage.ko.txt"
fi

# ------------------------------------------------------------------ 3. .deb
if has deb; then
    step ".deb"
    command -v dpkg-deb >/dev/null || die "dpkg-deb not found"
    d="$target/debroot"; rm -rf "$d"; cp -a "$stage" "$d"; mkdir -p "$d/DEBIAN"
    size=$(du -sk "$d/usr" | cut -f1)
    cat > "$d/DEBIAN/control" <<EOF
Package: shield
Version: $version
Section: utils
Priority: optional
Architecture: $deb_arch
Depends: libc6, libgtk-3-0, libxkbcommon0, libgl1
Recommends: util-linux
Installed-Size: $size
Maintainer: Shield <noreply@invalid>
Homepage: ${repo:-https://github.com}
Description: File encryption (XChaCha20-Poly1305, Argon2id) with .shd containers
 Shield encrypts files and folders into authenticated containers. Includes the windowed
 program (shield-gui), the console program (shield), file manager actions and the MIME type.
EOF
    install -m0755 installer/linux/postinst "$d/DEBIAN/postinst"
    install -m0755 installer/linux/postrm "$d/DEBIAN/postrm"
    out="$dist/shield_v${version}_${deb_arch}.deb"
    dpkg-deb --build --root-owner-group "$d" "$out" >/dev/null
    packages+=("$out")
fi

# ------------------------------------------------------------------ 4. AppImage
if has appimage; then
    step "AppImage"
    tool=${APPIMAGETOOL:-$(command -v appimagetool || command -v appimagetool-$native.AppImage || true)}
    if [ -z "$tool" ]; then
        echo "  appimagetool not found (APPIMAGETOOL=<path>): AppImage skipped" >&2
    else
        a="$target/AppDir"; rm -rf "$a"; cp -a "$stage" "$a"; rm -f "$a/usr/bin/"*.sig
        cat > "$a/AppRun" <<'EOF'
#!/bin/sh
# AppImage entry: `Shield.AppImage` opens the window; `Shield.AppImage cli <command>` runs the console program.
here=$(dirname "$(readlink -f "$0")")
if [ "${1:-}" = cli ]; then shift; exec "$here/usr/bin/shield" "$@"; fi
exec "$here/usr/bin/shield-gui" "$@"
EOF
        chmod 0755 "$a/AppRun"
        cp installer/linux/shield.desktop "$a/shield.desktop"
        cp "$target/icons/256x256/apps/shield.png" "$a/shield.png"
        out="$dist/Shield_v${version}_${native}.AppImage"
        ARCH=$native "$tool" --no-appstream "$a" "$out" >/dev/null
        chmod 0755 "$out"
        packages+=("$out")
    fi
fi

# ------------------------------------------------------------------ 5. .rpm (optional)
if has rpm; then
    step ".rpm"
    command -v rpmbuild >/dev/null || die "rpmbuild not found"
    r="$target/rpm"; rm -rf "$r"; mkdir -p "$r"/{BUILD,RPMS,SPECS,BUILDROOT}
    cat > "$r/SPECS/shield.spec" <<EOF
Name: shield
Version: $version
Release: 1
Summary: File encryption (XChaCha20-Poly1305, Argon2id)
License: see /usr/share/doc/shield/copyright
Requires: gtk3
%description
Shield encrypts files and folders into authenticated .shd containers.
%install
cp -a "$stage/." %{buildroot}/
%files
/usr/bin/shield
/usr/bin/shield-gui
$( [ $sign = y ] && printf '/usr/bin/shield.sig\n/usr/bin/shield-gui.sig\n' )
/usr/share/applications/shield.desktop
/usr/share/applications/shield-open.desktop
/usr/share/mime/packages/shield.xml
/usr/share/icons/hicolor/*/apps/shield.png
/usr/share/nemo/actions/shield-*.nemo_action
/usr/share/kio/servicemenus/shield.desktop
/usr/share/kservices5/ServiceMenus/shield.desktop
/usr/share/shield
/usr/share/doc/shield
EOF
    rpmbuild --define "_topdir $r" -bb "$r/SPECS/shield.spec" >/dev/null
    out="$dist/shield_v${version}_${native}.rpm"
    cp "$r"/RPMS/*/shield-"$version"-1.*.rpm "$out"
    packages+=("$out")
fi

# ------------------------------------------------------------------ 6. source zip
if has zip; then
    step "source zip"
    out="$dist/Shield_Project_v$vu.zip"
    python3 - "$ROOT" "$out" <<'EOF'
import os, re, sys, zipfile
root, out = sys.argv[1], sys.argv[2]
skip_dirs = {'target', 'dist', '.git', '.vs', '.idea', '.wix', '.claude', '.claude-flow', '.swarm', '.hive-mind', 'node_modules', '_unused'}
skip_ext = {'.msi', '.wixpdb', '.sig', '.gpg', '.kbx', '.key', '.pem', '.pfx', '.p12', '.zip', '.shd', '.tmp', '.part', '.asc'}
n = 0
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for d, dirs, files in os.walk(root):
        rel_d = os.path.relpath(d, root)
        if rel_d == '.':
            dirs[:] = [x for x in dirs if x not in skip_dirs and not x.startswith('dist_old_')]
        for f in files:
            rel = os.path.normpath(os.path.join(rel_d, f)).replace(os.sep, '/')
            fixture = rel.startswith('crates/shield-core/tests/fixtures/')
            pubkey = rel.startswith('keys/') and rel.endswith('.asc') and rel.count('/') == 1
            if f.startswith('.env') or f.startswith('.shd_'):
                continue
            if os.path.splitext(f)[1].lower() in skip_ext and not (fixture or pubkey):
                continue
            data = open(os.path.join(d, f), 'rb').read()
            if re.search(rb'(?m)^-----BEGIN [A-Z0-9 ]*(PRIVATE|SECRET) KEY( BLOCK)?-----', data):
                sys.exit('refusing to pack a private key: ' + rel)
            z.writestr(rel, data)
            n += 1
print(f'  {os.path.basename(out)} ({n} files)')
EOF
    packages+=("$out")
fi

# ------------------------------------------------------------------ 7. manifest, signatures, sums
manifest="$dist/Shield_v${version}_release.txt"
{
    if [ -n "$merge" ]; then
        [ "$(sed -n 1p "$merge")" = "Shield release manifest 1" ] && [ "$(sed -n 2p "$merge")" = "version $version" ] || die "merge manifest: wrong format or version"
        tail -n +3 "$merge" | grep -v '^$' | while read -r l; do [[ "$l" =~ ^sha256\ [0-9a-f]{64}\ [^[:space:]]+$ ]] || die "bad manifest line: $l"; echo "$l"; done
    fi
    for p in "${packages[@]}"; do echo "sha256 $(sha256sum "$p" | cut -d' ' -f1) $(basename "$p")"; done
} | awk '{ line[$3] = $0 } END { for (n in line) print line[n] }' | sort -k3 > "$manifest.body"
{ echo "Shield release manifest 1"; echo "version $version"; cat "$manifest.body"; } > "$manifest"; rm -f "$manifest.body"
if [ $sign = y ]; then
    step "signatures (passphrase: pinentry)"
    for p in "${packages[@]}" "$manifest"; do sign_file "$p"; done
    cp "$pubkey" "$dist/"
    cat > "$dist/VERIFY.txt" <<EOF
Shield $version - verifying the release / 배포 파일 검증
Key fingerprint / 서명 키 지문: $fpr      Public key / 공개키: $(basename "$pubkey")
1) gpg --import $(basename "$pubkey")
2) gpg --fingerprint $fpr   (compare with the fingerprint published elsewhere / 다른 경로로 받은 지문과 비교)
3) gpg --verify <file>.sig <file>   or   shield verify <file> <file>.sig --key $(basename "$pubkey")
4) sha256sum -c SHA256SUMS.txt
EOF
fi
(cd "$dist" && find . -maxdepth 1 -type f ! -name SHA256SUMS.txt -printf '%f\n' | sort | xargs sha256sum > SHA256SUMS.txt)
echo "done: dist/"; ls -l "$dist"
[ $sign = y ] || echo "built without signatures (no .sig); updates need signed releases" >&2
