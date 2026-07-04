#!/usr/bin/env bash
# Prepare a release PR branch by bumping build.zig.zon and committing it.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: mise run release -- [version] [--dry-run]

Prepares a release version-bump branch from origin/master.

Examples:
  mise run release
  mise run release -- 0.3.0
  mise run release -- v0.3.0
  mise run release -- --dry-run

Environment:
  RELEASE_REMOTE        Remote to release from (default: origin)
  RELEASE_BASE_BRANCH   Branch to release from (default: master)
  RELEASE_BRANCH_PREFIX Branch prefix (default: release-v)
EOF
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

release_remote="${RELEASE_REMOTE:-origin}"
base_branch="${RELEASE_BASE_BRANCH:-master}"
branch_prefix="${RELEASE_BRANCH_PREFIX:-release-v}"
dry_run=0
requested_version=""
current_manifest=""
tmp_manifest=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    *)
      if [[ -n "$requested_version" ]]; then
        echo "Unexpected argument: $1" >&2
        usage >&2
        exit 1
      fi
      requested_version="${1#v}"
      shift
      ;;
  esac
done

read_version() {
  sed -n 's/.*\.version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' "$1" | head -n 1
}

validate_version() {
  local version="$1"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

version_gt() {
  local lhs="$1"
  local rhs="$2"
  local lhs_major lhs_minor lhs_patch rhs_major rhs_minor rhs_patch

  IFS=. read -r lhs_major lhs_minor lhs_patch <<< "$lhs"
  IFS=. read -r rhs_major rhs_minor rhs_patch <<< "$rhs"

  if (( lhs_major != rhs_major )); then
    (( lhs_major > rhs_major ))
    return
  fi
  if (( lhs_minor != rhs_minor )); then
    (( lhs_minor > rhs_minor ))
    return
  fi
  (( lhs_patch > rhs_patch ))
}

next_patch_version() {
  local current="$1"
  local major minor patch

  IFS=. read -r major minor patch <<< "$current"
  printf '%s.%s.%s\n' "$major" "$minor" "$((patch + 1))"
}

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "release helper must run inside a git repository" >&2
  exit 1
fi

echo "Fetching ${release_remote}/${base_branch} and tags..."
git fetch "$release_remote" --tags

base_ref="${release_remote}/${base_branch}"
current_manifest="$(mktemp)"
trap 'rm -f "$current_manifest" "$tmp_manifest"' EXIT

git show "${base_ref}:build.zig.zon" > "$current_manifest"
current_version="$(read_version "$current_manifest")"
if [[ -z "$current_version" ]]; then
  echo "Failed to read X.Y.Z version from ${base_ref}:build.zig.zon" >&2
  exit 1
fi

if [[ -z "$requested_version" ]]; then
  new_version="$(next_patch_version "$current_version")"
else
  new_version="$requested_version"
fi

if ! validate_version "$new_version"; then
  echo "Invalid semantic version: $new_version" >&2
  exit 1
fi

if ! version_gt "$new_version" "$current_version"; then
  echo "New version $new_version must be greater than current version $current_version" >&2
  exit 1
fi

tag_name="v${new_version}"
release_branch="${branch_prefix}${new_version}"

if git rev-parse --verify "refs/tags/${tag_name}" >/dev/null 2>&1; then
  echo "Tag ${tag_name} already exists locally" >&2
  exit 1
fi

if git ls-remote --exit-code --tags "$release_remote" "$tag_name" >/dev/null 2>&1; then
  echo "Tag ${tag_name} already exists on ${release_remote}" >&2
  exit 1
fi

if git show-ref --verify --quiet "refs/heads/${release_branch}"; then
  echo "Local branch ${release_branch} already exists" >&2
  exit 1
fi

if git ls-remote --exit-code --heads "$release_remote" "$release_branch" >/dev/null 2>&1; then
  echo "Remote branch ${release_remote}/${release_branch} already exists" >&2
  exit 1
fi

echo "Current version: $current_version"
echo "Release version: $new_version"
echo "Release branch:  $release_branch"

if (( dry_run )); then
  echo "Dry run only; no files changed."
  exit 0
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree must be clean before preparing a release." >&2
  exit 1
fi

git switch -c "$release_branch" "$base_ref"

tmp_manifest="$(mktemp)"
awk -v ver="$new_version" '
  BEGIN { count = 0 }
  {
    if ($0 ~ /(\.version[[:space:]]*=[[:space:]]*")[0-9]+\.[0-9]+\.[0-9]+(")/) {
      if (count == 0) {
        sub(/(\.version[[:space:]]*=[[:space:]]*")[0-9]+\.[0-9]+\.[0-9]+(")/, ".version = \"" ver "\"")
        count++
      } else {
        print "Multiple build.zig.zon version entries encountered" > "/dev/stderr"
        exit 1
      }
    }
    print
  }
  END {
    if (count != 1) {
      print "Expected exactly one build.zig.zon version entry, updated " count > "/dev/stderr"
      exit 1
    }
  }
' build.zig.zon > "$tmp_manifest"
mv "$tmp_manifest" build.zig.zon

echo "Running release checks..."
zig build test
zig build -Dtarget=aarch64-freestanding-none

git add build.zig.zon
git commit -m "chore: release ${tag_name}"

cat <<EOF

Release bump commit created.

Next steps:
  git push -u ${release_remote} ${release_branch}
  gh pr create --base ${base_branch} --head ${release_branch} --title "chore: release ${tag_name}"
EOF
