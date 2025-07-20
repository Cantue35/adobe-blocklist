#!/usr/bin/env bash
set -euo pipefail

### Configuration & defaults
SOURCES_JSON="${SOURCES_JSON:-}"
PAYLOAD_FILE="${PAYLOAD_FILE:-payload.json}"          # Created by workflow step (if repository_dispatch)
OUTPUT_FILE="blocklist.lsrules"                      # Proper Little Snitch rule group JSON
NAME="${BLOCKLIST_NAME:-Adobe Telemetry Blocklist}"
MAINTAINER="${MAINTAINER:-Cantue}"
LICENSE="${LICENSE:-GPL-3.0}"
EXPIRES="${EXPIRES:-1 day (update frequency)}"
DATA_DIR="data"
SRC_DIR="$DATA_DIR/sources"
METRICS_FILE="$DATA_DIR/metrics.json"
TIMESTAMP_ISO="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
UPDATED_HUMAN="$(date -u +'%b %d, %Y, %I:%M %p (UTC)')"

# Enable inclusion of public IPv4 addresses (1 = include, 0 = disable)
INCLUDE_IPS="${INCLUDE_IPS:-1}"

mkdir -p "$SRC_DIR"

# Temp artifacts
CHANGED_SET_FILE="$(mktemp)"
ALL_DOMAINS_FILE="$(mktemp)"
IP_TMP_FILE="$(mktemp)"
TMP_OUTPUT="$(mktemp)"
TMP_DESC_FILE="$(mktemp)"

# Cleanup on exit
trap 'rm -f "$CHANGED_SET_FILE" "$ALL_DOMAINS_FILE" "$IP_TMP_FILE" "$TMP_OUTPUT" "$TMP_DESC_FILE"' EXIT

### Load sources configuration
if [[ -z "$SOURCES_JSON" ]]; then
  echo "ERROR: SOURCES_JSON env var is not set." >&2
  exit 1
fi
if ! echo "$SOURCES_JSON" | jq -e . >/dev/null 2>&1; then
  echo "ERROR: SOURCES_JSON is not valid JSON." >&2
  exit 1
fi

### Determine changed repositories (if any) from payload
if [[ -f "$PAYLOAD_FILE" ]] && jq -e '.changed_repos' "$PAYLOAD_FILE" >/dev/null 2>&1; then
  jq -r '.changed_repos[] | "\(.owner)/\(.repo)@\(.branch)"' "$PAYLOAD_FILE" | sort -u > "$CHANGED_SET_FILE"
else
  # If no payload, this file is empty, and is_changed() will always return true
  : > "$CHANGED_SET_FILE"
fi

### Helper: treat all as changed if list empty
is_changed() {
  local key="$1"
  # If the changed set file has no size (is empty), all sources are considered changed.
  if [[ ! -s "$CHANGED_SET_FILE" ]]; then
    return 0 # Success (is changed)
  fi
  grep -Fxq "$key" "$CHANGED_SET_FILE"
}

### Combined normalization & IP capture
# - Lowercases domains (stable dedup)
# - Preserves leading "*."
# - Validates domain syntax
# - Captures ONLY public IPv4 addresses (skips loopback, link-local, broadcast, RFC1918)
normalize_and_capture() {
  awk -v include_ips="$INCLUDE_IPS" -v ipfile="$IP_TMP_FILE" '
    function tolower_ascii(s,  i,c,out){ out=""; for(i=1;i<=length(s);i++){ c=substr(s,i,1); if(c>="A"&&c<="Z") c=tolower(c); out=out c } return out }
    function valid_domain(d){ if(length(d)<1||length(d)>253)return 0;if(d~/^\*\./){core=substr(d,3);if(core==""||core~/^\./)return 0}else core=d;if(core~/[^a-z0-9\.\-]/)return 0;if(core~/^\./||core~/\.$/)return 0;n=split(core,L,".");for(i=1;i<=n;i++){if(length(L[i])<1||length(L[i])>63)return 0;if(L[i]~/^-/||L[i]~/-$/)return 0}return 1 }
    function public_ipv4(ip){ if(ip~/^0\.0\.0\.0$/)return 0;if(ip~/^127\./)return 0;if(ip~/^169\.254\./)return 0;if(ip~/^255\.255\.255\.255$/)return 0;if(ip~/^10\./)return 0;if(ip~/^192\.168\./)return 0;if(ip~/^172\.(1[6-9]|2[0-9]|3[0-1])\./)return 0;return 1 }
    { gsub(/\r/,"");line=$0;sub(/#.*/,"",line);gsub(/^[ \t]+|[ \t]+$/,"",line);if(line=="")next;if(line~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ \t]+/){split(line,a,/[ \t]+/);lead=a[1];if(include_ips&&lead~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/&&public_ipv4(lead)){print lead>>ipfile}for(i=2;i<=length(a);i++){d=tolower_ascii(a[i]);if(d~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){if(include_ips&&public_ipv4(d))print d>>ipfile;continue}if(valid_domain(d))print d}next}if(line~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){if(include_ips&&public_ipv4(line))print line>>ipfile;next}d=tolower_ascii(line);if(valid_domain(d))print d }'
}


# Metrics accumulator
METRICS_JSON='[]'

process_source() {
  local id="$1" owner="$2" repo="$3" branch="$4" path="$5" format="$6"
  local key="${owner}/${repo}@${branch}"

  if ! is_changed "$key"; then
    echo "Skipping unchanged source: $key ($id)"
    return
  fi

  local raw_url="https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}"
  local raw_file="$SRC_DIR/${id}.raw"
  local dom_file="$SRC_DIR/${id}.domains"

  echo "Fetching $raw_url"
  if ! curl -fSL --compressed -o "$raw_file" "$raw_url"; then
    echo "WARNING: Failed to fetch $raw_url" >&2
    return
  fi

  local raw_count
  raw_count=$(grep -c . "$raw_file")

  normalize_and_capture < "$raw_file" | sort -u > "$dom_file"

  local valid_count
  valid_count=$(wc -l < "$dom_file")
  local invalid_count=$(( raw_count - valid_count ))
  cat "$dom_file" >> "$ALL_DOMAINS_FILE"

  # Safely add to the JSON array
  METRICS_JSON="$(jq \
    --arg id "$id" --arg repo "$key" --arg path "$path" --arg format "$format" \
    --argjson raw_count "$raw_count" --argjson valid_count "$valid_count" --argjson invalid_count "$invalid_count" \
    '. + [{id:$id, repo:$repo, path:$path, format:$format, raw:$raw_count, valid:$valid_count, invalid:$invalid_count}]' \
    <<<"$METRICS_JSON")"
}

# Use Process Substitution to iterate sources and preserve METRICS_JSON
while read -r src; do
  # Add checks for jq fields to prevent errors with malformed JSON
  id=$(jq -r '.id // "unknown"' <<<"$src")
  owner=$(jq -r '.owner // ""' <<<"$src")
  repo=$(jq -r '.repo // ""' <<<"$src")
  branch=$(jq -r '.branch // "main"' <<<"$src")
  path=$(jq -r '.path // ""' <<<"$src")
  format=$(jq -r '.format // "hosts"' <<<"$src")

  if [[ -z "$owner" || -z "$repo" || -z "$path" ]]; then
    echo "WARNING: Skipping source with missing owner, repo, or path: $id" >&2
    continue
  fi

  process_source "$id" "$owner" "$repo" "$branch" "$path" "$format"
done < <(jq -c '.[]' <<<"$SOURCES_JSON")


# Build final output
if [[ ! -s "$ALL_DOMAINS_FILE" ]]; then
  echo "No domains collected (possibly no changed sources)."
  jq -n --arg name "$NAME" --arg description "No changes at $UPDATED_HUMAN" \
      '{name:$name, description:$description, "denied-remote-domains":[]}' > "$TMP_OUTPUT"
else
  # Final deduplication
  sort -u -o "$ALL_DOMAINS_FILE" "$ALL_DOMAINS_FILE"
  TOTAL=$(wc -l < "$ALL_DOMAINS_FILE")

  if [[ "$TOTAL" -gt 200000 ]]; then
    echo "ERROR: Total domains ($TOTAL) exceed 200000 limit." >&2
    exit 1
  fi

  # Gather and deduplicate IPs (if any)
  TOTAL_IPS=0
  IP_FILE_DEDUP=""
  if [[ "$INCLUDE_IPS" == "1" && -s "$IP_TMP_FILE" ]]; then
    sort -u -o "$IP_TMP_FILE" "$IP_TMP_FILE"
    IP_FILE_DEDUP="$IP_TMP_FILE"
    TOTAL_IPS=$(wc -l < "$IP_FILE_DEDUP")
  fi

  # Implement robust Columnar Layout for the description banner
  LIST_SIZE=$(du -h "$ALL_DOMAINS_FILE" | cut -f1)
  LABELS=( "Entries" "Updated" "Size" "Maintainer" "Expires" "License" )
  VALUES=( "$TOTAL" "$UPDATED_HUMAN" "$LIST_SIZE" "$MAINTAINER" "$EXPIRES" "$LICENSE" )
  : "${MAX_META_WIDTH:=44}"

  max_label_len=0
  for lbl in "${LABELS[@]}"; do
    (( ${#lbl} > max_label_len )) && max_label_len=${#lbl}
  done
  COL1_WIDTH=$(( max_label_len + 2 ))

  BANNER_WIDTH=${#NAME}
  for i in "${!LABELS[@]}"; do
    line_len=$(( COL1_WIDTH + ${#VALUES[i]} ))
    (( line_len > BANNER_WIDTH )) && BANNER_WIDTH=$line_len
  done

  (( BANNER_WIDTH > MAX_META_WIDTH )) && BANNER_WIDTH=$MAX_META_WIDTH

  repeat_chars() {
    printf "%*s" "$2" "" | tr ' ' "$1"
  }

  BORDER_EQ=$(repeat_chars "=" "$BANNER_WIDTH")
  BORDER_DASH=$(repeat_chars "-" "$BANNER_WIDTH")

  TITLE="$NAME"
  (( ${#TITLE} > BANNER_WIDTH )) && TITLE="${TITLE:0:BANNER_WIDTH}"
  title_pad=$(( (BANNER_WIDTH - ${#TITLE}) / 2 ))
  right_pad=$(( BANNER_WIDTH - ${#TITLE} - title_pad ))

  VALUE_WIDTH_LIMIT=$(( BANNER_WIDTH - COL1_WIDTH ))
  (( VALUE_WIDTH_LIMIT < 3 )) && VALUE_WIDTH_LIMIT=3

  truncate_value() {
    local v="$1"
    if (( ${#v} > VALUE_WIDTH_LIMIT )); then
      v="${v:0:$(( VALUE_WIDTH_LIMIT - 3 ))}..."
    fi
    printf "%s" "$v"
  }

  build_line() {
    local label="$1" value="$2"
    printf "%-*s%s\n" "$COL1_WIDTH" "${label}:" "$(truncate_value "$value")"
  }

  {
    printf "%s\n" "$BORDER_EQ"
    printf "%*s%s%*s\n" "$title_pad" "" "$TITLE" "$right_pad" ""
    printf "%s\n" "$BORDER_DASH"
    for i in "${!LABELS[@]}"; do
      build_line "${LABELS[i]}" "${VALUES[i]}"
    done
    printf "%s\n" "$BORDER_EQ"
  } > "$TMP_DESC_FILE"

  # Use --rawfile to read description and build final JSON
  if (( TOTAL_IPS > 0 )); then
    jq -n \
      --arg name "$NAME" \
      --rawfile description "$TMP_DESC_FILE" \
      --argjson domains "$(jq -R 'select(length>0)' < "$ALL_DOMAINS_FILE" | jq -s '.')" \
      --argjson addrs "$(jq -R 'select(length>0)' < "$IP_FILE_DEDUP" | jq -s '.')" \
      '{name:$name, description:$description, "denied-remote-domains":$domains, "denied-remote-addresses":$addrs}' \
      > "$TMP_OUTPUT"
  else
    jq -n \
      --arg name "$NAME" \
      --rawfile description "$TMP_DESC_FILE" \
      --argjson domains "$(jq -R 'select(length>0)' < "$ALL_DOMAINS_FILE" | jq -s '.')" \
      '{name:$name, description:$description, "denied-remote-domains":$domains}' \
      > "$TMP_OUTPUT"
  fi
fi

# Build final metrics file
TOTAL_DOMAINS_FINAL=$( ( [[ -s "$ALL_DOMAINS_FILE" ]] && wc -l < "$ALL_DOMAINS_FILE" ) || echo 0 )
TOTAL_ADDRESSES_FINAL=$( ( [[ "$INCLUDE_IPS" == "1" && -s "$IP_TMP_FILE" ]] && wc -l < "$IP_TMP_FILE" ) || echo 0 )

jq -n --arg generated_at "$TIMESTAMP_ISO" \
   --argjson sources "$METRICS_JSON" \
   --argjson total_domains "$TOTAL_DOMAINS_FINAL" \
   --argjson total_addresses "$TOTAL_ADDRESSES_FINAL" \
   '{generated_at:$generated_at, total_domains:$total_domains, total_addresses:$total_addresses, sources:$sources}' \
   > "$METRICS_FILE"

# Atomic publish
mv "$TMP_OUTPUT" "$OUTPUT_FILE"

echo "Generated $OUTPUT_FILE and $METRICS_FILE at $TIMESTAMP_ISO"