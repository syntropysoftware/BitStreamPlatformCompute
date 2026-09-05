#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
BASE_BRANCH="${BITSTREAM_PLATFORMCOMPUTE_ACCEPTED_BRANCH:-main}"
REMOTE="${BITSTREAM_PLATFORMCOMPUTE_REMOTE:-origin}"

cd "$REPO_ROOT"

if [[ ! -d .git ]]; then
  printf 'STOPPED: %s is not a Git checkout.\n' "$REPO_ROOT" >&2
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  printf '%s\n' 'STOPPED: PlatformCompute checkout has local changes; evidence source identity is not clean.' >&2
  git status --short >&2
  exit 3
fi

# Refresh only local remote-tracking refs. This does not modify source files,
# production services, infrastructure, or the remote repository.
git fetch --prune "$REMOTE" >/dev/null

if ! git show-ref --verify --quiet "refs/remotes/${REMOTE}/${BASE_BRANCH}"; then
  printf 'STOPPED: accepted branch %s/%s is unavailable.\n' "$REMOTE" "$BASE_BRANCH" >&2
  exit 4
fi

HEAD_COMMIT="$(git rev-parse HEAD)"
ACCEPTED_COMMIT="$(git rev-parse "${REMOTE}/${BASE_BRANCH}")"
CURRENT_BRANCH="$(git branch --show-current)"

if ! git merge-base --is-ancestor "$HEAD_COMMIT" "${REMOTE}/${BASE_BRANCH}"; then
  printf '%s\n' 'STOPPED: current PlatformCompute source is not contained in accepted Git truth.' >&2
  printf 'CURRENT_BRANCH=%s\n' "$CURRENT_BRANCH" >&2
  printf 'CURRENT_HEAD=%s\n' "$HEAD_COMMIT" >&2
  printf 'ACCEPTED_BRANCH=%s/%s\n' "$REMOTE" "$BASE_BRANCH" >&2
  printf 'ACCEPTED_HEAD=%s\n' "$ACCEPTED_COMMIT" >&2
  printf '%s\n' 'Complete the repository promotion/merge before producing infrastructure evidence.' >&2
  exit 5
fi

printf 'SOURCE_ACCEPTANCE=PASS\n'
printf 'CURRENT_BRANCH=%s\n' "$CURRENT_BRANCH"
printf 'CURRENT_HEAD=%s\n' "$HEAD_COMMIT"
printf 'ACCEPTED_BRANCH=%s/%s\n' "$REMOTE" "$BASE_BRANCH"
printf 'ACCEPTED_HEAD=%s\n' "$ACCEPTED_COMMIT"
