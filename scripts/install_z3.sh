#!/bin/sh
# Installs the pinned Z3 release into DEST and prints the path of the executable as the last line.
#   tools/install_z3.sh DEST
# Windows (x64) and Linux (x64, glibc 2.39 or newer). The archive is checked against the release digest.
set -eu

version=4.16.0
[ $# -eq 1 ] || { echo "usage: $0 DEST" >&2; exit 2; }
mkdir -p "$1"
dest=$(cd "$1" && { pwd -W 2>/dev/null || pwd; })

case $(uname -s) in
    MINGW* | MSYS* | CYGWIN*)
        archive=z3-$version-x64-win.zip
        sha=de4d813e47202394a093547dbdb5699ee076529aa853463e007539775cd7e836
        exe=bin/z3.exe
        ;;
    Linux)
        archive=z3-$version-x64-glibc-2.39.zip
        sha=7288c49a5bd6dbafd7b0b0d1f65956b91672da24b08f09242919af159be3418e
        exe=bin/z3
        ;;
    *)
        echo "no pinned Z3 for $(uname -s); install Z3 $version and set ZV_Z3" >&2
        exit 1
        ;;
esac

folder=${archive%.zip}
if [ ! -f "$dest/$folder/$exe" ]; then
    curl -fsSL -o "$dest/$archive" "https://github.com/Z3Prover/z3/releases/download/z3-$version/$archive"
    echo "$sha  $dest/$archive" | sha256sum -c - >&2
    python3 -m zipfile -e "$dest/$archive" "$dest" 2>/dev/null || python -m zipfile -e "$dest/$archive" "$dest"
    chmod +x "$dest/$folder/$exe"
    rm -f "$dest/$archive"
fi
"$dest/$folder/$exe" --version >&2
echo "$dest/$folder/$exe"
