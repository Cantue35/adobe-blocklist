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

mkdir -p "$SRC_DIR"

# Temp artifacts
CHANGED_SET_FILE="$(mktemp)"
ALL_DOMAINS_FILE="$(mktemp)"
TMP_OUTPUT="$(mktemp)"

# Cleanup on exit
trap 'rm -f "$CHANGED_SET_FILE" "$ALL_DOMAINS_FILE" "$TMP_OUTPUT"' EXIT

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
  : > "$CHANGED_SET_FILE"
fi

### Helper: treat all as changed if list empty
is_changed() {
  local key="$1"
  if [[ ! -s "$CHANGED_SET_FILE" ]]; then
    return 0
  fi
  grep -Fxq "$key" "$CHANGED_SET_FILE"
}

### Domain normalization & validation
# Rules:
#   - Lowercase tokens (domains case-insensitive) for consistent dedup
#   - Preserve leading "*." wildcard
#   - Basic RFC constraints (label length, chars)
normalize_domains() {
  awk '
    function tolower_ascii(s,  i,c,out) {
      out=""
      for(i=1;i<=length(s);i++){
        c=substr(s,i,1)
        if(c>="A" && c<="Z"){ c=tolower(c) }
        out=out c
      }
      return out
    }
    function valid(d) {
      if (length(d) < 1 || length(d) > 253) return 0
      if (d ~ /^\*\./) {
        core = substr(d,3)
        if (core == "" || core ~ /^\./) return 0
      } else {
        core = d
      }
      if (core ~ /[^a-z0-9\.\-]/) return 0
      if (core ~ /^\./ || core ~ /\.$/) return 0
      n=split(core, L, ".")
      for(i=1;i<=n;i++){
        if(length(L[i])<1 || length(L[i])>63) return 0
        if (L[i] ~ /^-/ || L[i] ~ /-$/) return 0
      }
      return 1
    }
    {
      gsub(/\r/,"")
      line=$0
      sub(/#.*/,"", line)
      gsub(/^[ \t]+|[ \t]+$/,"", line)
      if(line=="") next

      if(line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ \t]+/){
        count = split(line, a, /[ \t]+/)
        for(i=2;i<=count;i++){
          d = tolower_ascii(a[i])
          if(d ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) continue
          if(valid(d)) print d
        }
        next
      }

      d = tolower_ascii(line)
      if(d ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
      if(valid(d)) print d
    }
  '
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
  raw_count=$(grep -v '^[[:space:]]*$' "$raw_file" | wc -l | tr -d ' ')

  normalize_domains < "$raw_file" | sort -u > "$dom_file"

  local valid_count
  valid_count=$(wc -l < "$dom_file" | tr -d ' ')
  local invalid_count=$(( raw_count - valid_count ))
  cat "$dom_file" >> "$ALL_DOMAINS_FILE"

  METRICS_JSON="$(jq \
    --arg id "$id" \
    --arg repo "$key" \
    --arg path "$path" \
    --arg format "$format" \
    --arg raw_count "$raw_count" \
    --arg valid_count "$valid_count" \
    --arg invalid_count "$invalid_count" \
    '. + [{id:$id, repo:$repo, path:$path, format:$format, raw:($raw_count|tonumber), valid:($valid_count|tonumber), invalid:($invalid_count|tonumber)}]' \
    <<<"$METRICS_JSON")"
}

# Iterate sources
jq -c '.[]' <<<"$SOURCES_JSON" | while read -r src; do
  id=$(jq -r '.id' <<<"$src")
  owner=$(jq -r '.owner' <<<"$src")
  repo=$(jq -r '.repo' <<<"$src")
  branch=$(jq -r '.branch' <<<"$src")
  path=$(jq -r '.path' <<<"$src")
  format=$(jq -r '.format // "hosts"' <<<"$src")
  process_source "$id" "$owner" "$repo" "$branch" "$path" "$format"
done

# Build final output
if [[ ! -s "$ALL_DOMAINS_FILE" ]]; then
  echo "No domains collected (possibly no changed sources)."
  jq -n --arg name "$NAME" --arg description "No changes at $UPDATED_HUMAN" \
      '{name:$name, description:$description, "denied-remote-domains":[]}' > "$TMP_OUTPUT"
else
  sort -u "$ALL_DOMAINS_FILE" > "${ALL_DOMAINS_FILE}.dedup"
  mv "${ALL_DOMAINS_FILE}.dedup" "$ALL_DOMAINS_FILE"
  TOTAL=$(wc -l < "$ALL_DOMAINS_FILE" | tr -d ' ')

  if [[ "$TOTAL" -gt 200000 ]]; then
    echo "ERROR: Total domains ($TOTAL) exceed 200000 limit." >&2
    exit 1
  fi

  # --- Dynamic robust metadata banner ---
  LIST_SIZE=$(du -h "$ALL_DOMAINS_FILE" | cut -f1)
  LABELS=( "Entries" "Updated" "Size" "Maintainer" "Expires" "License" )
  VALUES=( "$TOTAL" "$UPDATED_HUMAN" "$LIST_SIZE" "$MAINTAINER" "$EXPIRES" "$LICENSE" )

  : "${MIN_META_WIDTH:=40}"
  : "${MAX_META_WIDTH:=60}"
  : "${MIN_VALUE_WIDTH:=20}"

  max_label_len=0
  for lbl in "${LABELS[@]}"; do
    l=$(( ${#lbl} + 1 ))
    (( l > max_label_len )) && max_label_len=$l
  done
  label_width=$(( max_label_len + 1 ))
  (( label_width < 1 )) && label_width=1

  natural_width=${#NAME}
  for i in "${!LABELS[@]}"; do
    val="${VALUES[$i]}"
    line_len=$(( label_width + ${#val} ))
    (( line_len > natural_width )) && natural_width=$line_len
  done

  if (( natural_width < MIN_META_WIDTH )); then
    WIDTH=$MIN_META_WIDTH
  elif (( natural_width > MAX_META_WIDTH )); then
    WIDTH=$MAX_META_WIDTH
  else
    WIDTH=$natural_width
  fi

  min_allowed=$(( label_width + MIN_VALUE_WIDTH ))
  if (( WIDTH < min_allowed )); then
    WIDTH=$min_allowed
  fi

  value_width=$(( WIDTH - label_width ))
  if (( value_width < MIN_VALUE_WIDTH )); then
    value_width=$MIN_VALUE_WIDTH
    WIDTH=$(( label_width + value_width ))
  fi

  repeat_chars() {
    local ch="$1" count="$2" out=""
    while (( count > 0 )); do
      out+="$ch"
      ((count--))
    done
    printf "%s" "$out"
  }

  BORDER_EQ=$(repeat_chars "=" "$WIDTH")
  BORDER_DASH=$(repeat_chars "-" "$WIDTH")

  TITLE="$NAME"
  if (( ${#TITLE} > WIDTH )); then
    TITLE="${TITLE:0:WIDTH}"
  fi
  title_pad=$(( (WIDTH - ${#TITLE}) / 2 ))
  (( title_pad < 0 )) && title_pad=0
  right_pad=$(( WIDTH - ${#TITLE} - title_pad ))
  (( right_pad < 0 )) && right_pad=0

  truncate_value() {
    local v="$1"
    if (( ${#v} > value_width )); then
      if (( value_width > 3 )); then
        v="${v:0:$(( value_width - 3 ))}..."
      else
        v="${v:0:value_width}"
      fi
    fi
    printf "%s" "$v"
  }

  build_line() {
    local label="$1" value="$2"
    local label_colon="${label}:"
    printf "%-*s" "$label_width" "$label_colon"
    truncate_value "$value"
    printf "\n"
  }

  {
    printf "%s\n" "$BORDER_EQ"
    printf "%*s%s%*s\n" "$title_pad" "" "$TITLE" "$right_pad" ""
    printf "%s\n" "$BORDER_DASH"
    for i in "${!LABELS[@]}"; do
      build_line "${LABELS[$i]}" "${VALUES[$i]}"
    done
    printf "%s\n" "$BORDER_EQ"
  } > "${TMP_OUTPUT}.desc"

  DESCRIPTION="$(cat "${TMP_OUTPUT}.desc")"
  rm -f "${TMP_OUTPUT}.desc"

  jq -n \
    --arg name "$NAME" \
    --arg description "$DESCRIPTION" \
    --argjson domains "$(jq -R 'select(length>0)' < "$ALL_DOMAINS_FILE" | jq -s '.')" \
    '{name:$name, description:$description, "denied-remote-domains":$domains}' \
    > "$TMP_OUTPUT"
fi

# Metrics
jq --arg generated_at "$TIMESTAMP_ISO" \
   --argjson sources "$METRICS_JSON" \
   --arg total "$( ( [[ -s "$ALL_DOMAINS_FILE" ]] && wc -l < "$ALL_DOMAINS_FILE" ) || echo 0 )" \
   '{generated_at:$generated_at, total_domains:($total|tonumber), sources:$sources}' \
   > "$METRICS_FILE"

# Atomic publish
mv "$TMP_OUTPUT" "$OUTPUT_FILE"

echo "Generated $OUTPUT_FILE and $METRICS_FILE at $TIMESTAMP_ISO"