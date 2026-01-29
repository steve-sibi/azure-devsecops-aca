#!/usr/bin/env bash
set -euo pipefail

# aca_api.sh
#
# Small CLI wrapper for this repo's FastAPI "scanner" service.
#
# Requirements:
#   - curl
#   - python3 (used for JSON building/parsing and pretty-print fallback)
# Optional:
#   - jq (nicer JSON pretty-printing)
#
# Configuration precedence (highest first):
#   - API key:
#       1) --api-key
#       2) environment: $ACA_API_KEY, else $API_KEY
#       3) repo .env: ACA_API_KEY, else API_KEY
#   - Base URL:
#       1) --base-url
#       2) environment: $ACA_BASE_URL, else $API_URL
#       3) default: http://localhost:8000
#
# Notes:
#   - Most endpoints require an API key (everything except /, /healthz, /file).
#   - The .env reader is intentionally simple: it supports lines like KEY=value
#     or export KEY=value (optionally single/double-quoted). It does not
#     evaluate shell expansions.
#
# Defaults:
#   - API key header: --api-key-header, then $ACA_API_KEY_HEADER, then $API_KEY_HEADER, else X-API-Key
#   - History file: --history, then $ACA_API_HISTORY, else <repo>/.aca_api_history

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

die() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" > /dev/null 2>&1 || die "Missing dependency: $1"
}

require_deps() {
  require_cmd curl
  require_cmd python3
}

usage() {
  cat << 'USAGE'
Terminal helper for the FastAPI scanner.

Dependencies:
  curl, python3 (optional: jq for pretty JSON output)

Configuration (highest priority first):
  API key:
    1) --api-key
    2) $ACA_API_KEY, else $API_KEY
    3) .env: ACA_API_KEY, else API_KEY

  Base URL:
    1) --base-url
    2) $ACA_BASE_URL, else $API_URL
    3) http://localhost:8000

Usage:
  aca_api.sh [global options] <command> [args]

Global options:
  -b, --base-url URL         Base API URL (default: $ACA_BASE_URL, then $API_URL, else http://localhost:8000)
  -k, --api-key KEY          API key (default: $ACA_API_KEY, then $API_KEY, then .env ACA_API_KEY, then .env API_KEY)
      --api-key-header NAME  Header name (default: $ACA_API_KEY_HEADER, then $API_KEY_HEADER, else X-API-Key)
      --history PATH         Job history file (default: $ACA_API_HISTORY, else <repo>/.aca_api_history)
      --raw                  Print raw response (no pretty-print)
  -v, --verbose              Extra progress output (stderr)
  -h, --help                 Show help

Commands:
  health                                  GET /healthz
  scan-url <https://...>                  POST /scan (options: --source, --meta k=v, --meta-json, --force, --wait, --view)
  status <job_id>                         GET /scan/{job_id} (options: --view summary|full)
  wait <job_id>                           Poll /scan/{job_id} until completed/error (options: --interval, --timeout, --view)
  jobs                                    GET /jobs (options: --limit, --status STATUS[,STATUS...], --format lines|json)
  history                                 Local client history (options: --limit)
  clear-history
  clear-server-history                    DELETE /jobs (server-side history for your API key)
  screenshot <job_id> [-o PATH]           GET /scan/{job_id}/screenshot
  scan-file <path>                        POST /file/scan (multipart file upload)
  scan-payload <text> [--base64]          POST /file/scan (multipart text payload)

Examples:
  # Local (defaults to http://localhost:8000; reads ACA_API_KEY or API_KEY from .env if present)
  ./scripts/aca_api.sh health
  ./scripts/aca_api.sh scan-url https://example.com --wait
  ./scripts/aca_api.sh scan-file ./readme.md

  # Azure (one-off env vars for a single run)
  API_URL="https://<api-fqdn>" API_KEY="..." ./scripts/aca_api.sh scan-url https://example.com --wait

  # Azure (export once for your shell, then omit -b/-k)
  export API_URL="https://<api-fqdn>"
  export API_KEY="..."
  ./scripts/aca_api.sh jobs --limit 5
  ./scripts/aca_api.sh scan-url https://example.com --wait --view full

  # Inspect an existing job
  ./scripts/aca_api.sh status <job_id> --view full
  ./scripts/aca_api.sh wait <job_id> --timeout 300 --interval 2
  ./scripts/aca_api.sh screenshot <job_id> -o ./out.png

  # Filter jobs by status (comma-separated)
  ./scripts/aca_api.sh jobs --status queued,fetching,queued_scan,retrying --limit 50
  ./scripts/aca_api.sh jobs --format json --limit 10

  # Add metadata to a scan request
  ./scripts/aca_api.sh scan-url https://example.com \
    --meta env=dev --meta team=security \
    --meta-json '{"ticket":"ABC-123","owner":"me"}' \
    --wait

Troubleshooting:
  - "Submit succeeded but response did not include job_id": your API is returning
    a different JSON shape than expected; run with --raw and compare the response.
  - HTTP 401/403: check API key and header name (--api-key-header).
  - HTTP 400 for jobs --status: valid values are:
      pending,queued,fetching,queued_scan,retrying,completed,error
USAGE
}

trim_trailing_slash() {
  local s="$1"
  while [[ "$s" == */ ]]; do
    s="${s%/}"
  done
  printf '%s' "$s"
}

ALLOWED_JOB_STATUSES_CSV="pending,queued,fetching,queued_scan,retrying,completed,error"
ALLOWED_JOB_STATUSES_SPACES=" pending queued fetching queued_scan retrying completed error "
ALLOWED_VIEWS="summary|full"
ALLOWED_JOB_FORMATS="lines|json"

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

validate_view() {
  local view="$1"
  case "$view" in
    summary | full) ;;
    *) die "Invalid --view value: '$view'. Valid values: ${ALLOWED_VIEWS}" ;;
  esac
}

validate_jobs_format() {
  local format="$1"
  case "$format" in
    lines | json) ;;
    *) die "Invalid --format value: '$format'. Valid values: ${ALLOWED_JOB_FORMATS}" ;;
  esac
}

validate_uint_ge() {
  local name="$1"
  local value="$2"
  local min="$3"
  is_uint "$value" || die "$name must be a whole number >= ${min}"
  ((value >= min)) || die "$name must be >= ${min}"
}

validate_statuses_csv() {
  local csv="$1"
  local IFS=,
  local status

  for status in $csv; do
    status="${status#"${status%%[![:space:]]*}"}"
    status="${status%"${status##*[![:space:]]}"}"
    [[ -n "$status" ]] || die "--status must be a comma-separated list (no empty items). Valid values: ${ALLOWED_JOB_STATUSES_CSV}"
    case "$ALLOWED_JOB_STATUSES_SPACES" in
      *" $status "*) ;;
      *) die "Invalid --status value: '$status'. Valid values: ${ALLOWED_JOB_STATUSES_CSV}" ;;
    esac
  done
}

dotenv_get() {
  local key="$1"
  local file="$2"
  [[ -f "$file" ]] || return 1

  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Trim leading whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue

    if [[ "$line" == export\ * ]]; then
      line="${line#export }"
      line="${line#"${line%%[![:space:]]*}"}"
    fi

    [[ "$line" == "$key="* ]] || continue
    local value="${line#"$key"=}"

    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
      value="${value:1:-1}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
      value="${value:1:-1}"
    fi

    printf '%s' "$value"
    return 0
  done < "$file"

  return 1
}

json_pretty() {
  if command -v jq > /dev/null 2>&1; then
    jq .
  else
    python3 -m json.tool
  fi
}

json_field() {
  # Usage: json_field field.path [--optional]
  # Prints scalars as strings; prints dict/list as compact JSON.
  local field="$1"
  local optional="${2-}"

  if [[ -n "$optional" ]]; then
    python3 -c '
import json
import sys

field = sys.argv[1]
optional = ("--optional" in sys.argv[2:])
try:
  data = json.load(sys.stdin)
except Exception:
  sys.exit(0 if optional else 2)

val = data
for part in field.split("."):
  if isinstance(val, dict) and part in val:
    val = val[part]
  else:
    val = None
    break

if val is None:
  sys.exit(0 if optional else 1)
if isinstance(val, (dict, list)):
  print(json.dumps(val))
else:
  print(val)
' "$field" "$optional"
  else
    python3 -c '
import json
import sys

field = sys.argv[1]
try:
  data = json.load(sys.stdin)
except Exception:
  sys.exit(2)

val = data
for part in field.split("."):
  if isinstance(val, dict) and part in val:
    val = val[part]
  else:
    val = None
    break

if val is None:
  sys.exit(1)
if isinstance(val, (dict, list)):
  print(json.dumps(val))
else:
  print(val)
' "$field"
  fi
}

emit_json() {
  local body="$1"
  if [[ "${RAW:-0}" -eq 1 ]]; then
    echo "$body"
  else
    echo "$body" | json_pretty
  fi
}

http_json() {
  local method="$1"
  local url="$2"
  local body="${3-}"
  shift 3 || true

  local curl_args=(
    -sS
    -X "$method"
    "$url"
    -H "accept: application/json"
    -w $'\n%{http_code}'
  )
  if [[ -n "$body" ]]; then
    curl_args+=(-H "content-type: application/json" --data "$body")
  fi
  curl_args+=("$@")

  local resp status
  resp="$(curl "${curl_args[@]}")" || return 1
  status="${resp##*$'\n'}"
  resp="${resp%$'\n'*}"

  if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
    printf '%s' "$resp"
    return 0
  fi

  if [[ -n "$resp" ]]; then
    echo "$resp" >&2
  fi
  echo "HTTP $status" >&2
  return 1
}

http_form() {
  local url="$1"
  shift

  local resp status
  resp="$(curl -sS "$url" "$@" -w $'\n%{http_code}')" || return 1
  status="${resp##*$'\n'}"
  resp="${resp%$'\n'*}"

  if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
    printf '%s' "$resp"
    return 0
  fi

  if [[ -n "$resp" ]]; then
    echo "$resp" >&2
  fi
  echo "HTTP $status" >&2
  return 1
}

append_history() {
  local job_id="$1"
  local url="$2"
  local ts
  ts="$(date -u +%FT%TZ)"
  mkdir -p "$(dirname "$HISTORY_PATH")" 2> /dev/null || true
  printf '%s\t%s\t%s\t%s\n' "$ts" "$job_id" "$url" "$BASE_URL" >> "$HISTORY_PATH" || true
}

history_lines() {
  local limit="${1:-0}"
  [[ -f "$HISTORY_PATH" ]] || return 0
  if [[ "$limit" -gt 0 ]]; then
    tail -n "$limit" "$HISTORY_PATH"
  else
    cat "$HISTORY_PATH"
  fi
}

wait_for_scan_job() {
  local job_id="$1"
  local view="$2"
  local interval="$3"
  local timeout="$4"

  local start_epoch now_epoch elapsed
  start_epoch="$(date +%s)"

  local last_status=""
  local status body
  while true; do
    body="$(http_json GET "${BASE_URL}/scan/${job_id}?view=${view}" "" -H "${API_KEY_HEADER}: ${API_KEY}")"
    status="$(echo "$body" | json_field "status" --optional 2> /dev/null || true)"

    if [[ "$VERBOSE" -eq 1 ]]; then
      if [[ -n "$status" && "$status" != "$last_status" ]]; then
        echo "status=$status" >&2
        last_status="$status"
      fi
    fi

    if [[ "$status" == "completed" ]]; then
      echo "$body"
      return 0
    fi
    if [[ "$status" == "error" ]]; then
      echo "$body"
      return 1
    fi

    if [[ "$timeout" != "0" ]]; then
      now_epoch="$(date +%s)"
      elapsed=$((now_epoch - start_epoch))
      if ((elapsed >= timeout)); then
        die "Timed out after ${timeout}s waiting for job ${job_id} (last status: ${status:-unknown})"
      fi
    fi

    sleep "$interval"
  done
}

require_api_key() {
  [[ -n "${API_KEY:-}" ]] || die "Missing API key. Set --api-key, ACA_API_KEY, API_KEY, or add API_KEY to .env."
}

# Seed config from environment (can be overridden by CLI flags below).
BASE_URL="${ACA_BASE_URL:-${API_URL:-}}"
API_KEY="${ACA_API_KEY:-${API_KEY:-}}"
API_KEY_HEADER="${ACA_API_KEY_HEADER:-${API_KEY_HEADER:-}}"
HISTORY_PATH="${ACA_API_HISTORY:-}"
RAW=0
VERBOSE=0

require_deps

# Parse global options (must appear before the subcommand).
while [[ $# -gt 0 ]]; do
  case "$1" in
    -b | --base-url)
      [[ $# -ge 2 ]] || die "--base-url requires a value"
      BASE_URL="$2"
      shift 2
      ;;
    -k | --api-key)
      [[ $# -ge 2 ]] || die "--api-key requires a value"
      API_KEY="$2"
      shift 2
      ;;
    --api-key-header)
      [[ $# -ge 2 ]] || die "--api-key-header requires a value"
      API_KEY_HEADER="$2"
      shift 2
      ;;
    --history)
      [[ $# -ge 2 ]] || die "--history requires a path"
      HISTORY_PATH="$2"
      shift 2
      ;;
    --raw)
      RAW=1
      shift
      ;;
    -v | --verbose)
      VERBOSE=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      die "Unknown option: $1 (run with --help)"
      ;;
    *)
      break
      ;;
  esac
done

cmd="${1:-help}"
shift || true

# Finalize defaults after global option parsing.
if [[ -z "${BASE_URL:-}" ]]; then
  BASE_URL="http://localhost:8000"
fi
BASE_URL="$(trim_trailing_slash "$BASE_URL")"

if [[ -z "${API_KEY_HEADER:-}" ]]; then
  API_KEY_HEADER="X-API-Key"
fi

if [[ -z "${HISTORY_PATH:-}" ]]; then
  HISTORY_PATH="${REPO_ROOT}/.aca_api_history"
fi

# If no API key was provided via CLI/env vars, try repo .env as a convenience.
if [[ -z "${API_KEY:-}" ]]; then
  if api_key_from_dotenv="$(dotenv_get "ACA_API_KEY" "${REPO_ROOT}/.env" 2> /dev/null)"; then
    API_KEY="$api_key_from_dotenv"
  elif api_key_from_dotenv="$(dotenv_get "API_KEY" "${REPO_ROOT}/.env" 2> /dev/null)"; then
    API_KEY="$api_key_from_dotenv"
  fi
fi

# Dispatch subcommand.
case "$cmd" in
  help | -h | --help)
    usage
    ;;

  health)
    [[ $# -eq 0 ]] || die "health takes no arguments (run with --help)"
    body="$(http_json GET "${BASE_URL}/healthz" "")"
    emit_json "$body"
    ;;

  scan-url)
    [[ $# -ge 1 ]] || die "scan-url requires a URL"
    require_api_key

    url="$1"
    shift

    source=""
    meta_pairs=()
    meta_json=""
    force=0
    wait=0
    view="summary"

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --source)
          [[ $# -ge 2 ]] || die "--source requires a value"
          source="$2"
          shift 2
          ;;
        --meta)
          [[ $# -ge 2 ]] || die "--meta requires key=value"
          meta_pairs+=("$2")
          shift 2
          ;;
        --meta-json)
          [[ $# -ge 2 ]] || die "--meta-json requires a JSON object string"
          meta_json="$2"
          shift 2
          ;;
        --force)
          force=1
          shift
          ;;
        --wait)
          wait=1
          shift
          ;;
        --view)
          [[ $# -ge 2 ]] || die "--view requires a value (${ALLOWED_VIEWS})"
          validate_view "$2"
          view="$2"
          shift 2
          ;;
        *)
          die "Unknown scan-url option: $1 (valid: --source, --meta, --meta-json, --force, --wait, --view)"
          ;;
      esac
    done

    payload="$(
      URL="$url" SOURCE="$source" FORCE="$force" META_JSON="$meta_json" META_PAIRS="$(printf '%s\n' "${meta_pairs[@]-}")" \
        python3 - << 'PY'
import json
import os
import sys

url = os.environ.get("URL", "").strip()
if not url:
  raise SystemExit("missing url")

payload = {"url": url, "type": "url"}

source = os.environ.get("SOURCE", "").strip()
if source:
  payload["source"] = source

force = (os.environ.get("FORCE", "").strip() or "0").lower() in ("1", "true", "yes")
if force:
  payload["force"] = True

meta = {}
meta_json = os.environ.get("META_JSON", "").strip()
if meta_json:
  try:
    obj = json.loads(meta_json)
  except Exception as e:
    raise SystemExit(f"invalid --meta-json: {e}")
  if not isinstance(obj, dict):
    raise SystemExit("--meta-json must be a JSON object")
  meta.update(obj)

pairs = os.environ.get("META_PAIRS", "")
for line in pairs.splitlines():
  if not line.strip():
    continue
  if "=" not in line:
    raise SystemExit("--meta must be key=value")
  k, v = line.split("=", 1)
  k = k.strip()
  if not k:
    raise SystemExit("--meta key cannot be empty")
  meta[k] = v.strip()

if meta:
  payload["metadata"] = meta

print(json.dumps(payload, separators=(",", ":")))
PY
    )"

    submit_body="$(http_json POST "${BASE_URL}/scan" "$payload" -H "${API_KEY_HEADER}: ${API_KEY}")"
    job_id="$(echo "$submit_body" | json_field "job_id" --optional 2> /dev/null || true)"
    if [[ -z "$job_id" ]]; then
      echo "Submit response (no job_id found):" >&2
      echo "$submit_body" >&2
      die "Submit succeeded but response did not include job_id (try --raw or -v, and ensure jq/python3 is installed)"
    fi
    append_history "$job_id" "$url"

    if [[ "$wait" -eq 0 ]]; then
      emit_json "$submit_body"
      exit 0
    fi

    if [[ "$VERBOSE" -eq 1 ]]; then
      echo "JOB_ID=$job_id" >&2
    fi

    set +e
    final_body="$(wait_for_scan_job "$job_id" "$view" "2" "120")"
    rc=$?
    set -e

    emit_json "$final_body"
    exit "$rc"
    ;;

  status)
    [[ $# -ge 1 ]] || die "status requires a job_id"
    require_api_key

    job_id="$1"
    shift

    view="summary"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --view)
          [[ $# -ge 2 ]] || die "--view requires a value (${ALLOWED_VIEWS})"
          validate_view "$2"
          view="$2"
          shift 2
          ;;
        *)
          die "Unknown status option: $1 (valid: --view)"
          ;;
      esac
    done

    body="$(http_json GET "${BASE_URL}/scan/${job_id}?view=${view}" "" -H "${API_KEY_HEADER}: ${API_KEY}")"
    emit_json "$body"
    ;;

  wait)
    [[ $# -ge 1 ]] || die "wait requires a job_id"
    require_api_key

    job_id="$1"
    shift

    interval="2"
    timeout="120"
    view="summary"

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --interval)
          [[ $# -ge 2 ]] || die "--interval requires seconds (whole number, >= 1)"
          validate_uint_ge "--interval" "$2" 1
          interval="$2"
          shift 2
          ;;
        --timeout)
          [[ $# -ge 2 ]] || die "--timeout requires seconds (whole number, 0 for no timeout)"
          validate_uint_ge "--timeout" "$2" 0
          timeout="$2"
          shift 2
          ;;
        --view)
          [[ $# -ge 2 ]] || die "--view requires a value (${ALLOWED_VIEWS})"
          validate_view "$2"
          view="$2"
          shift 2
          ;;
        *)
          die "Unknown wait option: $1 (valid: --interval, --timeout, --view)"
          ;;
      esac
    done

    set +e
    final_body="$(wait_for_scan_job "$job_id" "$view" "$interval" "$timeout")"
    rc=$?
    set -e

    emit_json "$final_body"
    exit "$rc"
    ;;

  history)
    limit="0"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --limit)
          [[ $# -ge 2 ]] || die "--limit requires a number"
          validate_uint_ge "--limit" "$2" 0
          limit="$2"
          shift 2
          ;;
        *)
          die "Unknown history option: $1 (valid: --limit)"
          ;;
      esac
    done

    if [[ ! -f "$HISTORY_PATH" ]]; then
      echo "No history yet at: $HISTORY_PATH" >&2
      exit 0
    fi
    history_lines "$limit"
    ;;

  clear-history)
    [[ $# -eq 0 ]] || die "clear-history takes no arguments"
    rm -f "$HISTORY_PATH"
    echo "Cleared history: $HISTORY_PATH" >&2
    ;;

  clear-server-history)
    [[ $# -eq 0 ]] || die "clear-server-history takes no arguments"
    require_api_key
    body="$(http_json DELETE "${BASE_URL}/jobs" "" -H "${API_KEY_HEADER}: ${API_KEY}")"
    emit_json "$body"
    ;;

  jobs)
    require_api_key
    limit="20"
    statuses_csv=""
    format="lines"

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --limit)
          [[ $# -ge 2 ]] || die "--limit requires a number"
          validate_uint_ge "--limit" "$2" 1
          limit="$2"
          shift 2
          ;;
        --status)
          [[ $# -ge 2 ]] || die "--status requires a comma-separated list. Valid values: ${ALLOWED_JOB_STATUSES_CSV}"
          validate_statuses_csv "$2"
          statuses_csv="$2"
          shift 2
          ;;
        --format)
          [[ $# -ge 2 ]] || die "--format requires a value (${ALLOWED_JOB_FORMATS})"
          validate_jobs_format "$2"
          format="$2"
          shift 2
          ;;
        *)
          die "Unknown jobs option: $1 (valid: --limit, --status, --format)"
          ;;
      esac
    done

    qs="?limit=${limit}"
    if [[ -n "$statuses_csv" ]]; then
      qs="${qs}&status=${statuses_csv}"
    fi

    body="$(http_json GET "${BASE_URL}/jobs${qs}" "" -H "${API_KEY_HEADER}: ${API_KEY}")"

    if [[ "$format" == "json" ]]; then
      emit_json "$body"
      exit 0
    fi

    python3 - "$body" << 'PY'
import json
import sys

raw = sys.argv[1]
if not raw.strip():
  print("error: empty response from /jobs (check API_URL/base-url, API key, and that the API is updated)", file=sys.stderr)
  sys.exit(1)

try:
  data = json.loads(raw)
except json.JSONDecodeError:
  print("error: /jobs did not return JSON. Raw response:", file=sys.stderr)
  print(raw[:800], file=sys.stderr)
  sys.exit(1)

jobs = data.get("jobs") or []
if not isinstance(jobs, list):
  print("error: unexpected /jobs response shape (missing 'jobs' list). Raw JSON:", file=sys.stderr)
  print(raw[:800], file=sys.stderr)
  sys.exit(1)

print(f"{'job_id':36}  {'status':12}  {'submitted_at':20}  {'scanned_at':20}  url")
for j in jobs:
  if not isinstance(j, dict):
    continue
  job_id = str(j.get("job_id") or "")
  status = str(j.get("status") or "")
  submitted_at = str(j.get("submitted_at") or "")
  scanned_at = str(j.get("scanned_at") or "")
  url = str(j.get("url") or "")
  if len(url) > 80:
    url = url[:77] + "..."
  print(f"{job_id:36}  {status:12}  {submitted_at[:20]:20}  {scanned_at[:20]:20}  {url}")
PY
    ;;

  screenshot)
    [[ $# -ge 1 ]] || die "screenshot requires a job_id"
    require_api_key

    job_id="$1"
    shift

    out_path=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -o | --out)
          [[ $# -ge 2 ]] || die "-o/--out requires a path"
          out_path="$2"
          shift 2
          ;;
        *)
          die "Unknown screenshot option: $1 (valid: -o/--out)"
          ;;
      esac
    done

    hdr_file="$(mktemp)"
    body_file="$(mktemp)"
    status="$(curl -sS -D "$hdr_file" -o "$body_file" \
      -H "${API_KEY_HEADER}: ${API_KEY}" \
      "${BASE_URL}/scan/${job_id}/screenshot" \
      -w '%{http_code}')" || {
      rm -f "$hdr_file" "$body_file"
      die "curl failed"
    }

    if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
      if [[ -z "$out_path" ]]; then
        ctype="$(awk 'BEGIN{IGNORECASE=1} /^content-type:/ {print $0}' "$hdr_file" | tail -n 1 | cut -d: -f2- | tr -d '\r' | xargs)"
        ext="bin"
        case "$ctype" in
          image/jpeg) ext="jpg" ;;
          image/png) ext="png" ;;
        esac
        out_path="./${job_id}.${ext}"
      fi
      mv "$body_file" "$out_path"
      rm -f "$hdr_file"
      echo "$out_path"
      exit 0
    fi

    if [[ "$RAW" -eq 1 ]]; then
      cat "$body_file" >&2 || true
    else
      cat "$body_file" | json_pretty >&2 || cat "$body_file" >&2 || true
    fi
    rm -f "$hdr_file" "$body_file"
    die "HTTP $status"
    ;;

  scan-file)
    [[ $# -ge 1 ]] || die "scan-file requires a path"
    require_api_key
    file_path="$1"
    shift
    [[ $# -eq 0 ]] || die "scan-file takes exactly 1 argument: <path>"

    [[ -f "$file_path" ]] || die "File not found: $file_path"

    body="$(http_form "${BASE_URL}/file/scan" \
      -X POST \
      -H "${API_KEY_HEADER}: ${API_KEY}" \
      -F "file=@${file_path}")"

    emit_json "$body"
    ;;

  scan-payload)
    [[ $# -ge 1 ]] || die "scan-payload requires text"
    require_api_key

    payload_text="$1"
    shift

    payload_base64="false"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --base64)
          payload_base64="true"
          shift
          ;;
        *)
          die "Unknown scan-payload option: $1 (valid: --base64)"
          ;;
      esac
    done

    if [[ "$payload_base64" == "true" ]]; then
      body="$(http_form "${BASE_URL}/file/scan" \
        -X POST \
        -H "${API_KEY_HEADER}: ${API_KEY}" \
        -F "payload_base64=true" \
        -F "payload=${payload_text}")"
    else
      body="$(http_form "${BASE_URL}/file/scan" \
        -X POST \
        -H "${API_KEY_HEADER}: ${API_KEY}" \
        -F "payload=${payload_text}")"
    fi

    emit_json "$body"
    ;;

  *)
    die "Unknown command: $cmd (run with --help)"
    ;;
esac
