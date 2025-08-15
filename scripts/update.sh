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

# Enable inclusion of public IPv4 addresses into .domains and final output (1 = include, 0 = disable)
INCLUDE_IPS="${INCLUDE_IPS:-1}"

mkdir -p "$SRC_DIR"

# Temp artifacts (run-level collectors)
CHANGED_SET_FILE="$(mktemp)"
ALL_DOMAINS_FILE="$(mktemp)"     # non-IP entries
IP_RUN_TMP_FILE="$(mktemp)"      # IP entries (public IPv4)
TMP_OUTPUT="$(mktemp)"
TMP_DESC_FILE="$(mktemp)"

# Cleanup on exit
trap 'rm -f "$CHANGED_SET_FILE" "$ALL_DOMAINS_FILE" "$IP_RUN_TMP_FILE" "$TMP_OUTPUT" "$TMP_DESC_FILE"' EXIT

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

### Helper: treat all as changed if list empty (or FORCE_FULL_REBUILD set)
is_changed() {
  local key="$1"
  if [[ -n "${FORCE_FULL_REBUILD:-}" ]]; then
    return 0
  fi
  # If the changed set file has no size (is empty), all sources are considered changed.
  if [[ ! -s "$CHANGED_SET_FILE" ]]; then
    return 0 # Success (is changed)
  fi
  grep -Fxq "$key" "$CHANGED_SET_FILE"
}

### Normalization & optional IPv4 capture to STDOUT
# - Outputs VALID domains (lowercased, "*." preserved) to stdout
# - If INCLUDE_IPS=1, also outputs public IPv4 addresses to stdout
normalize_and_capture() {
  awk -v include_ips="$INCLUDE_IPS" '
    function tolower_ascii(s,  i,c,out){ out=""; for(i=1;i<=length(s);i++){ c=substr(s,i,1); if(c>="A"&&c<="Z") c=tolower(c); out=out c } return out }
    function valid_domain(d){
      if(length(d)<1||length(d)>253) return 0
      if(d~/^\*\./){ core=substr(d,3); if(core==""||core~/^\./) return 0 } else core=d
      if(core~/[^a-z0-9\.\-]/) return 0
      if(core~/^\./||core~/\.$/) return 0
      n=split(core,L,".")
      for(i=1;i<=n;i++){
        if(length(L[i])<1||length(L[i])>63) return 0
        if(L[i]~/^-/||L[i]~/-$/) return 0
      }
      return 1
    }
    function public_ipv4(ip){
      if(ip~/^0\.0\.0\.0$/)return 0
      if(ip~/^127\./)return 0
      if(ip~/^169\.254\./)return 0
      if(ip~/^255\.255\.255\.255$/)return 0
      if(ip~/^10\./)return 0
      if(ip~/^192\.168\./)return 0
      if(ip~/^172\.(1[6-9]|2[0-9]|3[0-1])\./)return 0
      return 1
    }
    {
      gsub(/\r/,"")
      line=$0
      sub(/#.*/,"",line)
      gsub(/^[ \t]+|[ \t]+$/,"",line)
      if(line=="") next

      # hosts-style lines: IP (maybe) followed by one or more names
      if(line~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ \t]+/){
        n=split(line,a,/[ \t]+/)
        lead=a[1]
        if(include_ips && public_ipv4(lead)) print lead
        for(i=2;i<=n;i++){
          d=tolower_ascii(a[i])
          if(d~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){
            if(include_ips && public_ipv4(d)) print d
            continue
          }
          if(valid_domain(d)) print d
        }
        next
      }

      # standalone IPv4
      if(line~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){
        if(include_ips && public_ipv4(line)) print line
        next
      }

      d=tolower_ascii(line)
      if(valid_domain(d)) print d
    }'
}

# Metrics accumulator
METRICS_JSON='[]'

# Append a mixed .domains file to run-level collectors (split IP vs non-IP)
append_mixed_to_collectors() {
  local domains_path="$1"
  if [[ -s "$domains_path" ]]; then
    awk '!/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' "$domains_path" >> "$ALL_DOMAINS_FILE"
    if [[ "$INCLUDE_IPS" == "1" ]]; then
      awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' "$domains_path" >> "$IP_RUN_TMP_FILE"
    fi
  fi
}

process_source() {
  local id="$1" owner="$2" repo="$3" branch="$4" path="$5" format="$6"
  local key="${owner}/${repo}@${branch}"

  local raw_url="https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}"
  local raw_file="$SRC_DIR/${id}.raw"
  local dom_file="$SRC_DIR/${id}.domains"

  if ! is_changed "$key"; then
    echo "Reusing unchanged source (cache): $key ($id)"
    append_mixed_to_collectors "$dom_file"

    if [[ -s "$dom_file" ]]; then
      local valid_count
      valid_count=$(wc -l < "$dom_file")
      METRICS_JSON="$(jq \
        --arg id "$id" --arg repo "$key" --arg path "$path" --arg format "$format" \
        --argjson raw_count "$valid_count" --argjson valid_count "$valid_count" --argjson invalid_count 0 \
        '. + [{id:$id, repo:$repo, path:$path, format:$format, raw:$raw_count, valid:$valid_count, invalid:$invalid_count, reused:true}]' \
        <<<"$METRICS_JSON")"
    else
      echo "WARNING: No cached .domains for unchanged source $id; it will be omitted." >&2
    fi
    return
  fi

  echo "Fetching $raw_url"
  if ! curl -fSL --compressed -o "$raw_file" "$raw_url"; then
    echo "WARNING: Failed to fetch $raw_url; falling back to cache if available." >&2
    append_mixed_to_collectors "$dom_file"
    if [[ -s "$dom_file" ]]; then
      local valid_count
      valid_count=$(wc -l < "$dom_file")
      METRICS_JSON="$(jq \
        --arg id "$id" --arg repo "$key" --arg path "$path" --arg format "$format" \
        --argjson raw_count "$valid_count" --argjson valid_count "$valid_count" --argjson invalid_count 0 \
        '. + [{id:$id, repo:$repo, path:$path, format:$format, raw:$raw_count, valid:$valid_count, invalid:$invalid_count, reused:true, note:"fetch_failed_used_cache"}]' \
        <<<"$METRICS_JSON")"
    fi
    return
  fi

  # Count raw non-empty lines (before normalization)
  local raw_count
  raw_count=$(grep -c . "$raw_file" || true)

  # Regenerate mixed .domains (domains +, optionally, IPs)
  normalize_and_capture < "$raw_file" | sort -u > "$dom_file"

  # Contribute to run-level collectors
  append_mixed_to_collectors "$dom_file"

  # Metrics
  local valid_count
  valid_count=$( ( [[ -s "$dom_file" ]] && wc -l < "$dom_file" ) || echo 0 )
  local invalid_count=$(( raw_count - valid_count ))
  (( invalid_count < 0 )) && invalid_count=0

  METRICS_JSON="$(jq \
    --arg id "$id" --arg repo "$key" --arg path "$path" --arg format "$format" \
    --argjson raw_count "$raw_count" --argjson valid_count "$valid_count" --argjson invalid_count "$invalid_count" \
    '. + [{id:$id, repo:$repo, path:$path, format:$format, raw:$raw_count, valid:$valid_count, invalid:$invalid_count, reused:false}]' \
    <<<"$METRICS_JSON")"
}

# Iterate sources and process (changed => refetch; unchanged => reuse cache)
while read -r src; do
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
if [[ ! -s "$ALL_DOMAINS_FILE" && ! -s "$IP_RUN_TMP_FILE" ]]; then
  echo "No entries collected (possibly no changed sources and no cache)."
  jq -n --arg name "$NAME" --arg description "No changes at $UPDATED_HUMAN" \
      '{name:$name, description:$description, "denied-remote-domains":[]}' > "$TMP_OUTPUT"
else
  # Final deduplication
  if [[ -s "$ALL_DOMAINS_FILE" ]]; then sort -u -o "$ALL_DOMAINS_FILE" "$ALL_DOMAINS_FILE"; fi
  if [[ -s "$IP_RUN_TMP_FILE" ]]; then sort -u -o "$IP_RUN_TMP_FILE" "$IP_RUN_TMP_FILE"; fi

  TOTAL=$( ( [[ -s "$ALL_DOMAINS_FILE" ]] && wc -l < "$ALL_DOMAINS_FILE" ) || echo 0 )
  if [[ "$TOTAL" -gt 200000 ]]; then
    echo "ERROR: Total domains ($TOTAL) exceed 200000 limit." >&2
    exit 1
  fi

  TOTAL_IPS=$( ( [[ -s "$IP_RUN_TMP_FILE" ]] && wc -l < "$IP_RUN_TMP_FILE" ) || echo 0 )

  # ======== Description banner (adaptive tab alignment to a fixed stop) ========
  EQ_LEN=${EQ_LEN:-33}
  DASH_LEN=${DASH_LEN:-44}
  CONTENT_WIDTH="$DASH_LEN"

  # Tab alignment controls (heuristic; tune if needed)
  TAB_WIDTH=${TAB_WIDTH:-8}
  TARGET_TAB_STOP=${TARGET_TAB_STOP:-4}  # values begin at tab stop #4

  DOM_SIZE="0"
  if [[ -s "$ALL_DOMAINS_FILE" ]]; then DOM_SIZE=$(du -h "$ALL_DOMAINS_FILE" | cut -f1); fi

  LABELS=( "Entries" "Updated" "Size" "Maintainer" "Expires" "License" )
  VALUES=( "$TOTAL" "$UPDATED_HUMAN" "$DOM_SIZE" "$MAINTAINER" "$EXPIRES" "$LICENSE" )

  repeat_chars() { printf "%*s" "$2" "" | tr ' ' "$1"; }
  BORDER_EQ=$(repeat_chars "=" "$EQ_LEN")
  BORDER_DASH=$(repeat_chars "-" "$DASH_LEN")

  TITLE="$NAME"
  (( ${#TITLE} > CONTENT_WIDTH )) && TITLE="${TITLE:0:CONTENT_WIDTH}"
  title_pad=$(( (CONTENT_WIDTH - ${#TITLE}) / 2 ))
  right_pad=$(( CONTENT_WIDTH - ${#TITLE} - title_pad ))

  VALUE_WIDTH_LIMIT=$(( CONTENT_WIDTH - 10 ))
  (( VALUE_WIDTH_LIMIT < 10 )) && VALUE_WIDTH_LIMIT=10
  truncate_value() {
    local v="$1"
    if (( ${#v} > VALUE_WIDTH_LIMIT )); then
      v="${v:0:$(( VALUE_WIDTH_LIMIT - 3 ))}..."
    fi
    printf "%s" "$v"
  }

  # Print "Label:" then enough tabs so the value starts at TARGET_TAB_STOP
  build_line_tabs() {
    local label="$1" value="$2"
    local lbl="${label}:"
    local len=${#lbl}
    local current_stop=$(( len / TAB_WIDTH + 1 ))       # which tab stop we’re at now
    local need=$(( TARGET_TAB_STOP - current_stop ))     # how many tabs to reach target
    (( need < 1 )) && need=1                             # at least one tab
    printf "%s" "$lbl"
    printf "%${need}s" "" | tr ' ' '\t'
    printf "%s\n" "$(truncate_value "$value")"
  }

  {
    printf "%s\n" "$BORDER_EQ"
    printf "%*s%s%*s\n" "$title_pad" "" "$TITLE" "$right_pad" ""
    printf "%s\n" "$BORDER_DASH"
    for i in "${!LABELS[@]}"; do
      build_line_tabs "${LABELS[i]}" "${VALUES[i]}"
    done
    printf "%s\n" "$BORDER_EQ"
  } > "$TMP_DESC_FILE"
  # ======== end banner ========

  # Build final JSON
  if (( TOTAL_IPS > 0 )); then
    jq -n \
      --arg name "$NAME" \
      --rawfile description "$TMP_DESC_FILE" \
      --argjson domains "$( ( [[ -s "$ALL_DOMAINS_FILE" ]] && jq -R 'select(length>0)' < "$ALL_DOMAINS_FILE" | jq -s '.' ) || echo '[]' )" \
      --argjson addrs "$( ( [[ -s "$IP_RUN_TMP_FILE" ]] && jq -R 'select(length>0)' < "$IP_RUN_TMP_FILE" | jq -s '.' ) || echo '[]' )" \
      '{name:$name, description:$description, "denied-remote-domains":$domains, "denied-remote-addresses":$addrs}' \
      > "$TMP_OUTPUT"
  else
    jq -n \
      --arg name "$NAME" \
      --rawfile description "$TMP_DESC_FILE" \
      --argjson domains "$( ( [[ -s "$ALL_DOMAINS_FILE" ]] && jq -R 'select(length>0)' < "$ALL_DOMAINS_FILE" | jq -s '.' ) || echo '[]' )" \
      '{name:$name, description:$description, "denied-remote-domains":$domains}' \
      > "$TMP_OUTPUT"
  fi
fi

# Build final metrics file
TOTAL_DOMAINS_FINAL=$( ( [[ -s "$ALL_DOMAINS_FILE" ]] && wc -l < "$ALL_DOMAINS_FILE" ) || echo 0 )
TOTAL_ADDRESSES_FINAL=$( ( [[ -s "$IP_RUN_TMP_FILE" ]] && wc -l < "$IP_RUN_TMP_FILE" ) || echo 0 )

jq -n --arg generated_at "$TIMESTAMP_ISO" \
   --argjson sources "$METRICS_JSON" \
   --argjson total_domains "$TOTAL_DOMAINS_FINAL" \
   --argjson total_addresses "$TOTAL_ADDRESSES_FINAL" \
   '{generated_at:$generated_at, total_domains:$total_domains, total_addresses:$total_addresses, sources:$sources}' \
   > "$METRICS_FILE"

# Atomic publish
mv "$TMP_OUTPUT" "$OUTPUT_FILE"
echo "Generated $OUTPUT_FILE and $METRICS_FILE at $TIMESTAMP_ISO"