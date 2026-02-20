#!/usr/bin/env bash
# repo-grep.sh — scan local Git repos with ripgrep and output CSV
# Requires: rg (ripgrep), git; jq is only needed for CSV output
#
# CSV columns: repo,file,line,query,snippet
#
# Examples:
#   # search multiple literals across all repos and write CSV
#   ./repo-grep.sh -d /code -F -q 's3://my-bucket' -q 'arn:aws:iam::123:role/ci' > matches.csv
#
#   # regex search with case-insensitive matching
#   ./repo-grep.sh -d /code -E -i -q '\b(dev|qa|stage|prod)-this-bucket\b' > matches.csv
#
#   # limit search to specific folders within each repo
#   ./repo-grep.sh -d /code -F -q 'this-bucket' --scope '.github/workflows' --scope 'infra' > matches.csv
#
#   # include .gitignore'd files and hidden folders
#   ./repo-grep.sh -d /code --no-ignore --hidden -q 'this-bucket' > matches.csv
#
#   # narrow to file globs (include and exclude)
#   ./repo-grep.sh -d /code -q 'my-bucket' --glob '**/*.tf' --glob '!**/vendor/**' > matches.csv
#
#   # raw ripgrep JSON for downstream processing (no jq)
#   ./repo-grep.sh -d /code -q 'my-bucket' --json-out > matches.json
#
#   # parallel scan with explicit concurrency
#   ./repo-grep.sh -d /code -q 'my-bucket' --jobs 8 > matches.csv

set -euo pipefail

ROOT=""
VERBOSE=0
LITERAL=0        # -F
IGNORE_CASE=0    # -i
SMART_CASE=0     # -S
NO_IGNORE=0      # -u (include .gitignore'd files)
HIDDEN=1         # include hidden (so .github/ is searched); exclude .git/ explicitly
JSON_OUT=0       # emit raw rg --json output with meta lines (skip jq)
MAX_SNIPPET=200
JOBS=0           # 0 = auto (nproc), 1 = sequential
declare -a QUERIES=()
QUERY_FILE=""
declare -a SCOPES=()     # repo-relative folders like ".github/workflows", "infra", "terraform"
declare -a GLOBS=()      # raw ripgrep -g patterns, e.g. '**/*.tf', '!node_modules/**'

usage() {
  cat <<EOF
Usage:
  $0 -d DIR [-q QUERY ...] [-f FILE] [--scope PATH ...] [--glob GLOB ...]
    [--literal|-F] [-E] [-i] [-S] [--no-ignore] [--hidden|--no-hidden]
    [--max-snippet N] [--json-out] [--jobs N] [-v]

Options:
  -d DIR            Root directory containing many git repos (required)
  -q QUERY          Search term (repeatable). Regex by default; use --literal for fixed string
  -f FILE           File with one query per line (added to any -q)
  --scope PATH      Limit search to this path inside each repo (repeatable). Example: ".github/workflows"
  --glob GLOB       Additional ripgrep glob include/exclude (repeatable). Example: '**/*.tf'  or  '!dist/**'
  --literal, -F     Treat queries as literal strings (ripgrep -F)
  -E                Treat queries as regex (default; overrides --literal)
  -i                Case-insensitive
  -S                Smart case (case-insensitive if pattern is all-lowercase)
  --no-ignore       Include files that are ignored by .gitignore (ripgrep -u)
  --hidden          Search hidden files/dirs too (default on)
  --no-hidden       Do not search hidden files/dirs
  --max-snippet N   Truncate snippet to N chars (default 200)
  --json-out        Emit raw ripgrep --json output plus meta lines; skip jq
  --jobs N          Parallel repo scans (default: auto from nproc; 1 = sequential)
  -v                Verbose

Notes:
  - Searches each repo independently from its root.
  - Hidden is ON by default to catch .github/**; we still exclude .git/ with -g '!.git'.
  - Use multiple --scope entries to OR folders within a repo (e.g., workflows + infra).
EOF
}

# --- arg parsing (supports long options) ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) ROOT="${2:-}"; shift 2 ;;
    -q) QUERIES+=("${2:-}"); shift 2 ;;
    -f) QUERY_FILE="${2:-}"; shift 2 ;;
    --scope) SCOPES+=("${2:-}"); shift 2 ;;
    --glob) GLOBS+=("${2:-}"); shift 2 ;;
    --literal|-F) LITERAL=1; shift ;;
    -E) LITERAL=0; shift ;;
    -i) IGNORE_CASE=1; shift ;;
    -S) SMART_CASE=1; shift ;;
    --no-ignore) NO_IGNORE=1; shift ;;
    --hidden) HIDDEN=1; shift ;;
    --no-hidden) HIDDEN=0; shift ;;
    --max-snippet) MAX_SNIPPET="${2:-200}"; shift 2 ;;
    --json-out) JSON_OUT=1; shift ;;
    --jobs) JOBS="${2:-}"; shift 2 ;;
    -v) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "$ROOT" && -d "$ROOT" ]] || { echo "Error: -d DIR is required and must exist." >&2; exit 1; }

if [[ -n "$QUERY_FILE" ]]; then
  [[ -f "$QUERY_FILE" ]] || { echo "Error: query file not found: $QUERY_FILE" >&2; exit 1; }
  while IFS= read -r line; do [[ -n "$line" ]] && QUERIES+=("$line"); done < "$QUERY_FILE"
fi
[[ ${#QUERIES[@]} -gt 0 ]] || { echo "Error: provide at least one -q or -f FILE" >&2; usage; exit 1; }

command -v rg >/dev/null || { echo "Missing dependency: ripgrep (rg)" >&2; exit 1; }
command -v git >/dev/null || { echo "Missing dependency: git" >&2; exit 1; }
if [[ $JSON_OUT -eq 0 ]]; then
  command -v jq >/dev/null || { echo "Missing dependency: jq" >&2; exit 1; }
fi

[[ $VERBOSE -eq 1 ]] && set -x

# helper: derive "owner/repo" label from git remote or fallback to folder
repo_label() {
  local repo_dir="$1"
  local remote
  if remote=$(git -C "$repo_dir" config --get remote.origin.url 2>/dev/null); then
    local id
    id="$(printf '%s' "$remote" | sed -E 's#.*[:/]{1}([^/:]+/[^/]+?)(\.git)?$#\1#')"
    [[ -n "$id" ]] && printf '%s' "$id" || basename "$repo_dir"
  else
    basename "$repo_dir"
  fi
}

# helper: escape a string for JSON value contexts
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//"/\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

scan_repo() {
  local repo="$1"

  # rebuild arrays when running in a subshell via xargs
  if [[ -n "${QUERIES_NL:-}" ]]; then
    mapfile -t QUERIES < <(printf '%s' "$QUERIES_NL")
  fi
  if [[ -n "${SCOPES_NL:-}" ]]; then
    mapfile -t SCOPES < <(printf '%s' "$SCOPES_NL")
  fi
  if [[ -n "${GLOBS_NL:-}" ]]; then
    mapfile -t GLOBS < <(printf '%s' "$GLOBS_NL")
  fi

  # sanity: ensure it's a usable repo root
  git -C "$repo" rev-parse --show-toplevel >/dev/null 2>&1 || { [[ $VERBOSE -eq 1 ]] && echo "WARN: skipping non-repo $repo" >&2; return 0; }
  local label
  label="$(repo_label "$repo")"

  # build ripgrep base args
  declare -a RG_ARGS=( --json -n --no-heading --color=never )
  (( LITERAL ))      && RG_ARGS+=( -F )
  (( IGNORE_CASE ))  && RG_ARGS+=( -i )
  (( SMART_CASE ))   && RG_ARGS+=( -S )
  (( NO_IGNORE ))    && RG_ARGS+=( -u )   # include .gitignore'd files
  (( HIDDEN ))       && RG_ARGS+=( --hidden )
  # always exclude the .git directory explicitly when hidden is on
  RG_ARGS+=( -g '!.git' )

  # scopes (repo-relative folders). Convert to -g 'scope/**' include globs.
  if [[ ${#SCOPES[@]} -gt 0 ]]; then
    local s
    for s in "${SCOPES[@]}"; do
      # trim any leading ./; standardize to 'path/**'
      s="${s#./}"
      RG_ARGS+=( -g "${s%/}/**" )
    done
  fi
  # raw extra globs
  if [[ ${#GLOBS[@]} -gt 0 ]]; then
    local g
    for g in "${GLOBS[@]}"; do RG_ARGS+=( -g "$g" ); done
  fi

  # run searches query-by-query so we can label which query matched
  local q
  for q in "${QUERIES[@]}"; do
    # Use a subshell with repo as CWD so -g paths are relative and clean
    if [[ $JSON_OUT -eq 1 ]]; then
      printf '{"type":"meta","repo":"%s","query":"%s"}\n' "$(json_escape "$label")" "$(json_escape "$q")"
      ( cd "$repo" && rg "${RG_ARGS[@]}" -e "$q" . 2>/dev/null ) || true
    else
      ( cd "$repo" && rg "${RG_ARGS[@]}" -e "$q" . 2>/dev/null ) \
      | jq -r --arg repo "$label" --arg query "$q" --argjson max "$MAX_SNIPPET" '
          select(.type=="match") as $m
          | $m.data.path.text as $path
          | $m.data.line_number as $line
          | ($m.data.lines.text | gsub("[\\r\\n]"; " ")) as $text
          | [$repo, $path, ($line|tostring), $query,
             ( if ($text|length) > $max then ($text[0:$max] + "…") else $text end
               | gsub("\""; "\"\"") )]
          | @csv
        ' || true
    fi
  done
}

# find git repos under ROOT (handles nested worktrees, submodules)
TMP_REPOS="$(mktemp)"; trap 'rm -f "$TMP_REPOS"' EXIT
find "$ROOT" -type d -name .git -print0 2>/dev/null | while IFS= read -r -d '' gm; do dirname "$gm"; done >> "$TMP_REPOS"
# if none found, maybe ROOT itself is a repo
if [[ ! -s "$TMP_REPOS" ]]; then
  if git -C "$ROOT" rev-parse --show-toplevel >/dev/null 2>&1; then
    printf '%s\n' "$ROOT" >> "$TMP_REPOS"
  fi
fi
mapfile -t REPOS < <(sort -u "$TMP_REPOS" | grep -v '^[[:space:]]*$')
[[ ${#REPOS[@]} -gt 0 ]] || { echo "No git repositories found under: $ROOT" >&2; exit 1; }

if [[ -n "$JOBS" && ! "$JOBS" =~ ^[0-9]+$ ]]; then
  echo "Error: --jobs must be a positive integer" >&2; exit 1
fi
if [[ -z "$JOBS" || "$JOBS" -eq 0 ]]; then
  if command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
  else
    JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
  fi
fi
(( JOBS < 1 )) && JOBS=1

# CSV header
if [[ $JSON_OUT -eq 0 ]]; then
  echo "repo,file,line,query,snippet"
fi

if (( JOBS > 1 )); then
  QUERIES_NL="$(printf '%s\n' "${QUERIES[@]}")"
  SCOPES_NL="$(printf '%s\n' "${SCOPES[@]}")"
  GLOBS_NL="$(printf '%s\n' "${GLOBS[@]}")"
  export LITERAL IGNORE_CASE SMART_CASE NO_IGNORE HIDDEN JSON_OUT MAX_SNIPPET VERBOSE
  export QUERIES_NL SCOPES_NL GLOBS_NL
  export -f repo_label json_escape scan_repo
  printf '%s\0' "${REPOS[@]}" \
    | xargs -0 -n1 -P "$JOBS" bash -c 'scan_repo "$@"' _
else
  for repo in "${REPOS[@]}"; do
    scan_repo "$repo"
  done
fi

