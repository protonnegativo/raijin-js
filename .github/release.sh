#!/usr/bin/env bash
# Tags HEAD with the next release and creates its GitHub Release. Usage: release.sh [patch|minor|major]
# [base]. With a base commit (the push's "before"), it skips when the change since then touches only
# files that are not in the binary. release.yml runs it on every push; the drift job runs it after it
# pushes an engine bump, because a push made with GITHUB_TOKEN does not trigger release.yml. It also
# starts goreleaser.yml for the new tag, since the tag it pushes does not start it either.
set -euo pipefail

bump=${1:-patch}
base=${2:-}

git fetch --tags --force --quiet
if [ -n "$(git tag --points-at HEAD --list 'v*')" ]; then
  echo "HEAD is already tagged: $(git tag --points-at HEAD --list 'v*' | tr '\n' ' ')"
  exit 0
fi

# bench fixtures, docs and workflows are not in the binary; engines.json is (embedded), so it releases
if [ -n "$base" ] && git cat-file -e "$base^{commit}" 2>/dev/null; then
  changed=$(git diff --name-only "$base" HEAD)
  binary=$(printf '%s\n' "$changed" | grep -v -E '^bench/fixtures/|\.md$|^docs/|^\.github/' | grep -v '^$' || true)
  if [ -z "$binary" ]; then
    echo "no binary change since $base; nothing to release"
    exit 0
  fi
fi

last=$(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1 || true)
if [ -z "$last" ]; then
  tag=v0.1.0
else
  IFS=. read -r major minor patch <<< "${last#v}"
  case $bump in
    major) tag=v$((major + 1)).0.0 ;;
    minor) tag=v$major.$((minor + 1)).0 ;;
    patch) tag=v$major.$minor.$((patch + 1)) ;;
    *) echo "unknown bump: $bump" >&2; exit 1 ;;
  esac
fi

git tag -a "$tag" -m "$tag"
git push origin "$tag"
gh release create "$tag" --title "$tag" --generate-notes
# a tag and a Release created with GITHUB_TOKEN do not start other workflows: build the binaries explicitly
gh workflow run goreleaser.yml -f tag="$tag"
echo "released $tag"
