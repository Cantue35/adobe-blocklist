#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C
umask 022

# -----------------------------------------------------------------------------
# Logging and error handling
# -----------------------------------------------------------------------------

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARNING: %s\n' "$*" >&2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

on_error() {
  local exit_code=$?
  local line_no=${BASH_LINENO[0]:-${LINENO}}
  printf 'ERROR: command failed (exit=%d, line=%s): %s\n' \
    "$exit_code" "$line_no" "$BASH_COMMAND" >&2
  exit "$exit_code"
}

trap on_error ERR

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SOURCES_JSON="${SOURCES_JSON:-}"
PAYLOAD_FILE="${PAYLOAD_FILE:-payload.json}"
OUTPUT_FILE="${OUTPUT_FILE:-blocklist.lsrules}"

NAME="${BLOCKLIST_NAME:-Adobe Telemetry Blocklist}"
MAINTAINER="${MAINTAINER:-Cantue}"
LICENSE="${LICENSE:-GPL-3.0}"
EXPIRES="${EXPIRES:-1 day (update frequency)}"

DATA_DIR="${DATA_DIR:-data}"
SRC_DIR="${SRC_DIR:-${DATA_DIR}/sources}"
METRICS_FILE="${METRICS_FILE:-${DATA_DIR}/metrics.json}"

INCLUDE_IPS="${INCLUDE_IPS:-1}"
FORCE_FULL_REBUILD="${FORCE_FULL_REBUILD:-0}"
ALLOW_EMPTY_OUTPUT="${ALLOW_EMPTY_OUTPUT:-0}"
ALLOW_LARGE_DROP="${ALLOW_LARGE_DROP:-0}"

MAX_DOMAINS="${MAX_DOMAINS:-200000}"
MAX_ADDRESSES="${MAX_ADDRESSES:-200000}"
MIN_DOMAINS="${MIN_DOMAINS:-1}"
MIN_SOURCE_ENTRIES="${MIN_SOURCE_ENTRIES:-1}"
MAX_DOMAIN_DROP_PERCENT="${MAX_DOMAIN_DROP_PERCENT:-80}"

CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-15}"
CURL_MAX_TIME="${CURL_MAX_TIME:-120}"
CURL_RETRIES="${CURL_RETRIES:-3}"
CURL_RETRY_DELAY="${CURL_RETRY_DELAY:-2}"

TIMESTAMP_ISO="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
UPDATED_HUMAN="$(date -u +'%b %d, %Y, %I:%M %p (UTC)')"

# -----------------------------------------------------------------------------
# Validation helpers
# -----------------------------------------------------------------------------

require_command() {
  local command_name=$1
  command -v "$command_name" >/dev/null 2>&1 \
    || die "Required command not found: $command_name"
}

normalize_boolean() {
  local value=${1,,}
  case "$value" in
    1 | true | yes | on) printf '1' ;;
    0 | false | no | off | '') printf '0' ;;
    *) return 1 ;;
  esac
}

require_nonnegative_integer() {
  local name=$1 value=$2
  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] \
    || die "$name must be a non-negative integer; got: $value"
}

for command_name in jq curl awk sort grep wc date mktemp mkdir mv chmod dirname rm tr; do
  require_command "$command_name"
done

INCLUDE_IPS="$(normalize_boolean "$INCLUDE_IPS")" \
  || die "INCLUDE_IPS must be a boolean value"
FORCE_FULL_REBUILD="$(normalize_boolean "$FORCE_FULL_REBUILD")" \
  || die "FORCE_FULL_REBUILD must be a boolean value"
ALLOW_EMPTY_OUTPUT="$(normalize_boolean "$ALLOW_EMPTY_OUTPUT")" \
  || die "ALLOW_EMPTY_OUTPUT must be a boolean value"
ALLOW_LARGE_DROP="$(normalize_boolean "$ALLOW_LARGE_DROP")" \
  || die "ALLOW_LARGE_DROP must be a boolean value"

for numeric_setting in \
  MAX_DOMAINS MAX_ADDRESSES MIN_DOMAINS MIN_SOURCE_ENTRIES MAX_DOMAIN_DROP_PERCENT \
  CURL_CONNECT_TIMEOUT CURL_MAX_TIME CURL_RETRIES CURL_RETRY_DELAY; do
  require_nonnegative_integer "$numeric_setting" "${!numeric_setting}"
done

(( MAX_DOMAIN_DROP_PERCENT <= 100 )) \
  || die "MAX_DOMAIN_DROP_PERCENT must be between 0 and 100"
(( MAX_DOMAINS >= MIN_DOMAINS )) \
  || die "MAX_DOMAINS must be greater than or equal to MIN_DOMAINS"

[[ -n "$SOURCES_JSON" ]] || die "SOURCES_JSON environment variable is not set"

if ! jq -e '
  type == "array"
  and length > 0
  and all(.[];
    type == "object"
    and (.id | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]*$"))
    and (.owner | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9_.-]*$"))
    and (.repo | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9_.-]*$"))
    and ((.branch // "main") | type == "string" and length > 0 and (test("[[:cntrl:]]") | not))
    and (.path | type == "string" and length > 0 and (startswith("/") | not) and (test("[[:cntrl:]]") | not))
    and ((.format // "auto") | type == "string" and length > 0 and (test("[[:cntrl:]]") | not))
  )
  and ((map(.id) | length) == (map(.id) | unique | length))
' <<<"$SOURCES_JSON" >/dev/null; then
  die "SOURCES_JSON must be a non-empty array of valid source objects with unique, filename-safe ids"
fi

EXPECTED_SOURCE_COUNT="$(jq -r 'length' <<<"$SOURCES_JSON")"

mkdir -p "$SRC_DIR" "$(dirname "$OUTPUT_FILE")" "$(dirname "$METRICS_FILE")"

RUN_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/adobe-blocklist.XXXXXX")"
CHANGED_SET_FILE="$RUN_TMP_DIR/changed-repositories.txt"
ALL_DOMAINS_FILE="$RUN_TMP_DIR/all-domains.txt"
ALL_ADDRESSES_FILE="$RUN_TMP_DIR/all-addresses.txt"
METRICS_NDJSON_FILE="$RUN_TMP_DIR/source-metrics.ndjson"
TMP_DESCRIPTION_FILE="$RUN_TMP_DIR/description.txt"
TMP_OUTPUT_FILE="$(mktemp "${OUTPUT_FILE}.tmp.XXXXXX")"
TMP_METRICS_FILE="$(mktemp "${METRICS_FILE}.tmp.XXXXXX")"

cleanup() {
  set +e
  rm -rf "$RUN_TMP_DIR"
  rm -f "$TMP_OUTPUT_FILE" "$TMP_METRICS_FILE"
}
trap cleanup EXIT

: >"$CHANGED_SET_FILE"
: >"$ALL_DOMAINS_FILE"
: >"$ALL_ADDRESSES_FILE"
: >"$METRICS_NDJSON_FILE"

# -----------------------------------------------------------------------------
# Dispatch payload handling
# -----------------------------------------------------------------------------

HAS_CHANGE_PAYLOAD=0

if [[ -f "$PAYLOAD_FILE" ]]; then
  if ! jq -e '
    type == "object"
    and (.changed_repos | type == "array")
    and all(.changed_repos[];
      type == "object"
      and (.owner | type == "string" and length > 0)
      and (.repo | type == "string" and length > 0)
      and ((.branch // "main") | type == "string" and length > 0)
    )
  ' "$PAYLOAD_FILE" >/dev/null; then
    die "Payload file exists but does not contain a valid changed_repos array: $PAYLOAD_FILE"
  fi

  HAS_CHANGE_PAYLOAD=1
  jq -r '
    .changed_repos[]
    | (.owner + "/" + .repo + "@" + (.branch // "main"))
  ' "$PAYLOAD_FILE" | sort -u >"$CHANGED_SET_FILE"
fi

is_changed() {
  local repository_key=$1

  if (( FORCE_FULL_REBUILD == 1 )); then
    return 0
  fi

  # No dispatch payload means a manual/local invocation: rebuild every source.
  if (( HAS_CHANGE_PAYLOAD == 0 )); then
    return 0
  fi

  grep -Fxq "$repository_key" "$CHANGED_SET_FILE"
}

# -----------------------------------------------------------------------------
# Source normalization
# -----------------------------------------------------------------------------

# Converts common hosts/domain/adblock/dnsmasq source forms into a sorted mixed
# list of valid domains and, when enabled, publicly routable IPv4 addresses.
# A tab-separated statistics record is written to the supplied stats file:
#   input_records<TAB>emitted_entries<TAB>rejected_records
normalize_source() {
  local input_file=$1
  local output_file=$2
  local stats_file=$3

  awk -v include_ips="$INCLUDE_IPS" -v stats_file="$stats_file" '
    function trim(value) {
      gsub(/^[ \t]+|[ \t]+$/, "", value)
      return value
    }

    function valid_ipv4(ip, parts, count, i) {
      count = split(ip, parts, ".")
      if (count != 4) return 0

      for (i = 1; i <= 4; i++) {
        if (parts[i] !~ /^[0-9]+$/) return 0
        if ((parts[i] + 0) < 0 || (parts[i] + 0) > 255) return 0
      }
      return 1
    }

    function public_ipv4(ip, parts, a, b) {
      if (!valid_ipv4(ip, parts)) return 0

      a = parts[1] + 0
      b = parts[2] + 0

      if (a == 0) return 0                         # This network
      if (a == 10) return 0                        # RFC 1918
      if (a == 100 && b >= 64 && b <= 127) return 0 # Shared address space
      if (a == 127) return 0                       # Loopback
      if (a == 169 && b == 254) return 0           # Link-local
      if (a == 172 && b >= 16 && b <= 31) return 0 # RFC 1918
      if (a == 192 && b == 0) return 0             # IETF protocol assignments
      if (a == 192 && b == 168) return 0           # RFC 1918
      if (a == 198 && (b == 18 || b == 19)) return 0 # Benchmarking
      if (a == 198 && b == 51 && (parts[3] + 0) == 100) return 0 # TEST-NET-2
      if (a == 203 && b == 0 && (parts[3] + 0) == 113) return 0  # TEST-NET-3
      if (a >= 224) return 0                       # Multicast/reserved

      return 1
    }

    function normalize_domain(domain, wildcard, core, labels, count, i) {
      domain = tolower(trim(domain))
      sub(/\.$/, "", domain)

      if (length(domain) < 1 || length(domain) > 253) return ""

      wildcard = ""
      core = domain
      if (domain ~ /^\*\./) {
        wildcard = "*."
        core = substr(domain, 3)
      }

      if (core == "" || core ~ /^\./ || core ~ /\.$/ || core ~ /\.\./) return ""
      if (core ~ /[^a-z0-9.-]/) return ""

      count = split(core, labels, ".")
      for (i = 1; i <= count; i++) {
        if (length(labels[i]) < 1 || length(labels[i]) > 63) return ""
        if (labels[i] ~ /^-/ || labels[i] ~ /-$/) return ""
      }

      return wildcard core
    }

    function emit_candidate(candidate, normalized) {
      candidate = trim(candidate)
      if (candidate == "") return 0

      # Adblock exception rules are allow-rules, not block entries.
      if (candidate ~ /^@@/) return 0

      # Basic Adblock/uBlock host rule: ||example.com^ or ||example.com^$option
      if (candidate ~ /^\|\|/) {
        candidate = substr(candidate, 3)
        sub(/\^.*/, "", candidate)
      }

      # Remove surrounding whitespace again after syntax extraction.
      candidate = trim(candidate)
      if (candidate == "") return 0

      # Numeric dotted strings are IP candidates only; never reinterpret an
      # invalid address such as 999.999.999.999 as a domain name.
      if (candidate ~ /^[0-9.]+$/) {
        if (include_ips && public_ipv4(candidate)) {
          print candidate
          return 1
        }
        return 0
      }

      normalized = normalize_domain(candidate)
      if (normalized != "") {
        print normalized
        return 1
      }

      return 0
    }

    {
      gsub(/\r/, "")
      line = $0
      sub(/#.*/, "", line)
      line = trim(line)

      if (line == "" || line ~ /^!/) next

      input_records++
      line_emitted = 0

      # dnsmasq forms such as server=/example.com/ and
      # address=/example.com/0.0.0.0
      if (line ~ /^(server|address)=\//) {
        dnsmasq_value = line
        sub(/^[^=]+=\//, "", dnsmasq_value)
        split(dnsmasq_value, dnsmasq_parts, "/")
        line_emitted += emit_candidate(dnsmasq_parts[1])
      } else {
        field_count = split(line, fields, /[ \t]+/)

        # hosts-style records: an IPv4 address followed by one or more names.
        if (field_count >= 2 && valid_ipv4(fields[1])) {
          if (include_ips && public_ipv4(fields[1])) {
            line_emitted += emit_candidate(fields[1])
          }
          for (i = 2; i <= field_count; i++) {
            line_emitted += emit_candidate(fields[i])
          }
        } else if (field_count == 1) {
          line_emitted += emit_candidate(fields[1])
        }
      }

      emitted_entries += line_emitted
      if (line_emitted == 0) rejected_records++
    }

    END {
      printf "%d\t%d\t%d\n", \
        input_records + 0, emitted_entries + 0, rejected_records + 0 \
        > stats_file
    }
  ' "$input_file" | sort -u >"$output_file"
}

count_lines() {
  local file_path=$1
  if [[ -s "$file_path" ]]; then
    wc -l <"$file_path" | awk '{print $1}'
  else
    printf '0\n'
  fi
}

append_to_collectors() {
  local normalized_file=$1

  [[ -s "$normalized_file" ]] || return 0

  awk '!/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' \
    "$normalized_file" >>"$ALL_DOMAINS_FILE"

  if (( INCLUDE_IPS == 1 )); then
    awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' \
      "$normalized_file" >>"$ALL_ADDRESSES_FILE"
  fi
}

write_metric() {
  local id=$1 repository_key=$2 path=$3 format=$4
  local raw_count=$5 valid_count=$6 invalid_count=$7 duplicate_count=$8
  local reused=$9 status=${10} note=${11:-}

  jq -cn \
    --arg id "$id" \
    --arg repo "$repository_key" \
    --arg path "$path" \
    --arg format "$format" \
    --arg status "$status" \
    --arg note "$note" \
    --argjson raw "$raw_count" \
    --argjson valid "$valid_count" \
    --argjson invalid "$invalid_count" \
    --argjson duplicates_removed "$duplicate_count" \
    --argjson reused "$reused" \
    '{
      id: $id,
      repo: $repo,
      path: $path,
      format: $format,
      raw: $raw,
      valid: $valid,
      invalid: $invalid,
      duplicates_removed: $duplicates_removed,
      reused: $reused,
      status: $status
    } + if $note == "" then {} else {note: $note} end' \
    >>"$METRICS_NDJSON_FILE"
}

use_normalized_cache() {
  local id=$1 repository_key=$2 path=$3 format=$4
  local raw_file=$5 normalized_file=$6 status=$7 note=${8:-}
  local raw_count valid_count invalid_count duplicates_removed emitted_count
  local existing_valid_count

  existing_valid_count="$(count_lines "$normalized_file")"
  valid_count="$existing_valid_count"
  raw_count="$valid_count"
  invalid_count=0
  duplicates_removed=0

  if [[ -s "$raw_file" ]]; then
    local stats_file refreshed_file refreshed_valid_count
    stats_file="$RUN_TMP_DIR/${id}.cache.stats"
    refreshed_file="$(mktemp "${normalized_file}.tmp.XXXXXX")"
    normalize_source "$raw_file" "$refreshed_file" "$stats_file"

    IFS=$'\t' read -r raw_count emitted_count invalid_count <"$stats_file"
    refreshed_valid_count="$(count_lines "$refreshed_file")"
    duplicates_removed=$(( emitted_count > refreshed_valid_count ? emitted_count - refreshed_valid_count : 0 ))

    if (( refreshed_valid_count >= MIN_SOURCE_ENTRIES || ALLOW_EMPTY_OUTPUT == 1 )); then
      valid_count="$refreshed_valid_count"
      chmod 0644 "$refreshed_file"
      mv "$refreshed_file" "$normalized_file"
    elif (( existing_valid_count >= MIN_SOURCE_ENTRIES )); then
      warn "Re-normalizing cached raw data for '$id' produced only $refreshed_valid_count entries; keeping the existing normalized cache"
      rm -f "$refreshed_file"
      raw_count="$existing_valid_count"
      valid_count="$existing_valid_count"
      invalid_count=0
      duplicates_removed=0
      status="stale_cache"
      if [[ -n "$note" ]]; then
        note="${note};cached_raw_below_minimum_kept_domains_cache"
      else
        note="cached_raw_below_minimum_kept_domains_cache"
      fi
    else
      rm -f "$refreshed_file"
      die "Cached source '$id' produced fewer than MIN_SOURCE_ENTRIES ($MIN_SOURCE_ENTRIES), and no usable normalized cache exists"
    fi
  elif (( valid_count < MIN_SOURCE_ENTRIES && ALLOW_EMPTY_OUTPUT == 0 )); then
    die "Normalized cache for source '$id' contains only $valid_count entries; expected at least $MIN_SOURCE_ENTRIES"
  fi

  append_to_collectors "$normalized_file"
  write_metric \
    "$id" "$repository_key" "$path" "$format" \
    "$raw_count" "$valid_count" "$invalid_count" "$duplicates_removed" \
    true "$status" "$note"
}

fetch_source() {
  local url=$1 destination=$2

  curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --compressed \
    --retry "$CURL_RETRIES" \
    --retry-delay "$CURL_RETRY_DELAY" \
    --retry-all-errors \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" \
    --max-time "$CURL_MAX_TIME" \
    --user-agent 'adobe-blocklist-updater/2.0 (+https://github.com/Cantue35/adobe-blocklist)' \
    --output "$destination" \
    "$url"
}

process_source() {
  local id=$1 owner=$2 repo=$3 branch=$4 path=$5 format=$6
  local repository_key="${owner}/${repo}@${branch}"
  local raw_url="https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}"
  local raw_file="${SRC_DIR}/${id}.raw"
  local normalized_file="${SRC_DIR}/${id}.domains"

  case "${format,,}" in
    auto | hosts | host | pihole | domains | domain | plain | adblock | dnsmasq) ;;
    *) warn "Source '$id' uses unknown format '$format'; automatic parsing will be used" ;;
  esac

  if ! is_changed "$repository_key"; then
    if [[ -s "$raw_file" || -s "$normalized_file" ]]; then
      log "Reprocessing unchanged source from cache: $repository_key ($id)"
      use_normalized_cache \
        "$id" "$repository_key" "$path" "$format" \
        "$raw_file" "$normalized_file" \
        "reused_cache"
      return 0
    fi

    warn "No cache exists for unchanged source '$id'; fetching it to restore a complete build"
  fi

  log "Fetching $raw_url"

  local fetched_file normalized_temp stats_file
  fetched_file="$(mktemp "${raw_file}.tmp.XXXXXX")"
  normalized_temp="$(mktemp "${normalized_file}.tmp.XXXXXX")"
  stats_file="$RUN_TMP_DIR/${id}.fetch.stats"

  if fetch_source "$raw_url" "$fetched_file" && [[ -s "$fetched_file" ]]; then
    local raw_count emitted_count invalid_count valid_count duplicates_removed

    normalize_source "$fetched_file" "$normalized_temp" "$stats_file"
    IFS=$'\t' read -r raw_count emitted_count invalid_count <"$stats_file"
    valid_count="$(count_lines "$normalized_temp")"
    duplicates_removed=$(( emitted_count > valid_count ? emitted_count - valid_count : 0 ))

    if (( valid_count < MIN_SOURCE_ENTRIES && ALLOW_EMPTY_OUTPUT == 0 )); then
      rm -f "$fetched_file" "$normalized_temp"

      if [[ -s "$raw_file" || -s "$normalized_file" ]]; then
        warn "Fetched source '$id' normalized to only $valid_count entries; using the last cached copy"
        use_normalized_cache \
          "$id" "$repository_key" "$path" "$format" \
          "$raw_file" "$normalized_file" \
          "stale_cache" "fetched_content_below_minimum_used_cache"
        return 0
      fi

      die "Fetched source '$id' normalized to only $valid_count entries; expected at least $MIN_SOURCE_ENTRIES"
    fi

    chmod 0644 "$fetched_file" "$normalized_temp"
    mv "$fetched_file" "$raw_file"
    mv "$normalized_temp" "$normalized_file"

    append_to_collectors "$normalized_file"
    write_metric \
      "$id" "$repository_key" "$path" "$format" \
      "$raw_count" "$valid_count" "$invalid_count" "$duplicates_removed" \
      false "fetched"
    return 0
  fi

  rm -f "$fetched_file" "$normalized_temp"

  if [[ -s "$raw_file" || -s "$normalized_file" ]]; then
    warn "Fetch failed for $raw_url; using the last cached copy"
    use_normalized_cache \
      "$id" "$repository_key" "$path" "$format" \
      "$raw_file" "$normalized_file" \
      "stale_cache" "fetch_failed_used_cache"
    return 0
  fi

  die "Fetch failed and no cache is available for source '$id' ($raw_url)"
}

# -----------------------------------------------------------------------------
# Process configured sources
# -----------------------------------------------------------------------------

while IFS=$'\t' read -r id owner repo branch path format; do
  process_source "$id" "$owner" "$repo" "$branch" "$path" "$format"
done < <(
  jq -r '
    .[]
    | [
        .id,
        .owner,
        .repo,
        (.branch // "main"),
        .path,
        (.format // "auto")
      ]
    | @tsv
  ' <<<"$SOURCES_JSON"
)

# -----------------------------------------------------------------------------
# Finalize, guard, and validate output
# -----------------------------------------------------------------------------

sort -u -o "$ALL_DOMAINS_FILE" "$ALL_DOMAINS_FILE"
sort -u -o "$ALL_ADDRESSES_FILE" "$ALL_ADDRESSES_FILE"

TOTAL_DOMAINS="$(count_lines "$ALL_DOMAINS_FILE")"
TOTAL_ADDRESSES="$(count_lines "$ALL_ADDRESSES_FILE")"

if (( TOTAL_DOMAINS == 0 && TOTAL_ADDRESSES == 0 && ALLOW_EMPTY_OUTPUT == 0 )); then
  die "No entries were collected; refusing to replace the existing blocklist with an empty output"
fi

if (( TOTAL_DOMAINS < MIN_DOMAINS && ALLOW_EMPTY_OUTPUT == 0 )); then
  die "Domain count ($TOTAL_DOMAINS) is below MIN_DOMAINS ($MIN_DOMAINS)"
fi

(( TOTAL_DOMAINS <= MAX_DOMAINS )) \
  || die "Domain count ($TOTAL_DOMAINS) exceeds MAX_DOMAINS ($MAX_DOMAINS)"
(( TOTAL_ADDRESSES <= MAX_ADDRESSES )) \
  || die "Address count ($TOTAL_ADDRESSES) exceeds MAX_ADDRESSES ($MAX_ADDRESSES)"

if [[ -f "$METRICS_FILE" ]] && jq -e '.total_domains | numbers' "$METRICS_FILE" >/dev/null 2>&1; then
  PREVIOUS_TOTAL_DOMAINS="$(jq -r '.total_domains' "$METRICS_FILE")"

  if (( PREVIOUS_TOTAL_DOMAINS > 0 && ALLOW_LARGE_DROP == 0 )); then
    MIN_ALLOWED_AFTER_DROP=$(( PREVIOUS_TOTAL_DOMAINS * (100 - MAX_DOMAIN_DROP_PERCENT) / 100 ))
    if (( TOTAL_DOMAINS < MIN_ALLOWED_AFTER_DROP )); then
      die "Domain count dropped from $PREVIOUS_TOTAL_DOMAINS to $TOTAL_DOMAINS, exceeding the allowed ${MAX_DOMAIN_DROP_PERCENT}% decrease; set ALLOW_LARGE_DROP=1 for an intentional reduction"
    fi
  fi
fi

human_size() {
  local bytes=$1
  awk -v bytes="$bytes" '
    function fmt(value, unit) {
      if (value >= 10 || unit == "B") return sprintf("%.0f %s", value, unit)
      return sprintf("%.1f %s", value, unit)
    }
    BEGIN {
      split("B KiB MiB GiB", units, " ")
      value = bytes + 0
      unit = 1
      while (value >= 1024 && unit < 4) {
        value /= 1024
        unit++
      }
      print fmt(value, units[unit])
    }
  '
}

DOMAIN_BYTES="$(wc -c <"$ALL_DOMAINS_FILE" | awk '{print $1}')"
ADDRESS_BYTES="$(wc -c <"$ALL_ADDRESSES_FILE" | awk '{print $1}')"
TOTAL_INPUT_SIZE="$(human_size $(( DOMAIN_BYTES + ADDRESS_BYTES )))"

DESCRIPTION_WIDTH=52
DESCRIPTION_BORDER="$(printf '%*s' "$DESCRIPTION_WIDTH" '' | tr ' ' '=')"
DESCRIPTION_RULE="$(printf '%*s' "$DESCRIPTION_WIDTH" '' | tr ' ' '-')"

{
  printf '%s\n' "$DESCRIPTION_BORDER"
  printf '%s\n' "$NAME"
  printf '%s\n' "$DESCRIPTION_RULE"
  printf '%-13s %s\n' 'Domains:' "$TOTAL_DOMAINS"
  printf '%-13s %s\n' 'Addresses:' "$TOTAL_ADDRESSES"
  printf '%-13s %s\n' 'Updated:' "$UPDATED_HUMAN"
  printf '%-13s %s\n' 'List size:' "$TOTAL_INPUT_SIZE"
  printf '%-13s %s\n' 'Maintainer:' "$MAINTAINER"
  printf '%-13s %s\n' 'Expires:' "$EXPIRES"
  printf '%-13s %s\n' 'License:' "$LICENSE"
  printf '%s\n' "$DESCRIPTION_BORDER"
} >"$TMP_DESCRIPTION_FILE"

# Large domain/address lists are read from files. They are never expanded into
# command-line arguments, avoiding the kernel ARG_MAX / per-argument limits.
if (( TOTAL_ADDRESSES > 0 )); then
  jq -n \
    --arg name "$NAME" \
    --rawfile description "$TMP_DESCRIPTION_FILE" \
    --rawfile domains_text "$ALL_DOMAINS_FILE" \
    --rawfile addresses_text "$ALL_ADDRESSES_FILE" \
    '
      def nonempty_lines($text):
        $text | split("\n") | map(select(length > 0));

      {
        name: $name,
        description: $description,
        "denied-remote-domains": nonempty_lines($domains_text),
        "denied-remote-addresses": nonempty_lines($addresses_text)
      }
    ' >"$TMP_OUTPUT_FILE"
else
  jq -n \
    --arg name "$NAME" \
    --rawfile description "$TMP_DESCRIPTION_FILE" \
    --rawfile domains_text "$ALL_DOMAINS_FILE" \
    '
      def nonempty_lines($text):
        $text | split("\n") | map(select(length > 0));

      {
        name: $name,
        description: $description,
        "denied-remote-domains": nonempty_lines($domains_text)
      }
    ' >"$TMP_OUTPUT_FILE"
fi

jq -s \
  --arg generated_at "$TIMESTAMP_ISO" \
  --argjson total_domains "$TOTAL_DOMAINS" \
  --argjson total_addresses "$TOTAL_ADDRESSES" \
  '
    {
      generated_at: $generated_at,
      total_domains: $total_domains,
      total_addresses: $total_addresses,
      stale_source_count: ([.[] | select(.status == "stale_cache")] | length),
      sources: .
    }
  ' "$METRICS_NDJSON_FILE" >"$TMP_METRICS_FILE"

if ! jq -e '
  type == "object"
  and (.name | type == "string" and length > 0)
  and (.description | type == "string")
  and (."denied-remote-domains" | type == "array")
  and all(."denied-remote-domains"[]; type == "string" and length > 0)
  and (
    (has("denied-remote-addresses") | not)
    or (
      ."denied-remote-addresses" | type == "array"
      and all(.[]; type == "string" and length > 0)
    )
  )
' "$TMP_OUTPUT_FILE" >/dev/null; then
  die "Generated blocklist failed JSON schema validation"
fi

if ! jq -e '
  type == "object"
  and (.generated_at | type == "string")
  and (.total_domains | type == "number")
  and (.total_addresses | type == "number")
  and (.sources | type == "array")
  and all(.sources[];
    type == "object"
    and (.id | type == "string" and length > 0)
    and (.status | type == "string" and length > 0)
  )
' "$TMP_METRICS_FILE" >/dev/null; then
  die "Generated metrics failed JSON schema validation"
fi

OUTPUT_DOMAIN_COUNT="$(jq -r '."denied-remote-domains" | length' "$TMP_OUTPUT_FILE")"
OUTPUT_ADDRESS_COUNT="$(jq -r '."denied-remote-addresses" // [] | length' "$TMP_OUTPUT_FILE")"
PROCESSED_SOURCE_COUNT="$(jq -r '.sources | length' "$TMP_METRICS_FILE")"

[[ "$PROCESSED_SOURCE_COUNT" == "$EXPECTED_SOURCE_COUNT" ]] \
  || die "Processed source count ($PROCESSED_SOURCE_COUNT) does not match configured source count ($EXPECTED_SOURCE_COUNT)"
[[ "$OUTPUT_DOMAIN_COUNT" == "$TOTAL_DOMAINS" ]] \
  || die "Generated domain array count does not match the collector count"
[[ "$OUTPUT_ADDRESS_COUNT" == "$TOTAL_ADDRESSES" ]] \
  || die "Generated address array count does not match the collector count"

chmod 0644 "$TMP_OUTPUT_FILE" "$TMP_METRICS_FILE"
mv "$TMP_OUTPUT_FILE" "$OUTPUT_FILE"
mv "$TMP_METRICS_FILE" "$METRICS_FILE"

log "Generated $OUTPUT_FILE and $METRICS_FILE at $TIMESTAMP_ISO"
log "Domains: $TOTAL_DOMAINS; addresses: $TOTAL_ADDRESSES"
