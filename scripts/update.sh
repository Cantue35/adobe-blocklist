#!/bin/bash

set -e

# Define constants
PIHOLE_URL="https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/main/pihole.txt"
URLS_FILE="data/urls.txt"
BLOCKLIST_FILE="blocklist.txt"
REPO_URL="https://x-access-token:$PAT_TOKEN@github.com/Cantue35/adobe-blocklist.git"

# Create data directory if it doesn't exist
mkdir -p data

# Fetch the latest pihole.txt directly from a-dove-is-dumb and process it
curl -s $PIHOLE_URL | \
grep -v '^#' | \
awk -F. '{OFS="."; for(i=NF; i>0; i--) printf("%s%s", $i, (i>1?OFS:ORS))}' | \
sort | \
awk -F. '{OFS="."; for(i=NF; i>0; i--) printf("%s%s", $i, (i>1?OFS:ORS))}' > $URLS_FILE

# Count entries
entry_count=$(wc -l < $URLS_FILE)

# Get file size
file_size=$(du -h $URLS_FILE | cut -f1)

# Get current date and time in UTC
updated_time=$(date -u +"%b %d, %Y, %I:%M %p (UTC)")

# Define the width for labels and values
label_width=15  # width of the label field
value_width=35  # width of the value field
line_width=$((label_width + value_width))  # total line width

# Center-align the title
title="Adobe Telemetry Blocklist"
title_padding=$(( (line_width - ${#title}) / 2 ))
centered_title=$(printf "%*s%s%*s" $title_padding "" "$title" $(( line_width - ${#title} - title_padding )) "")

# Prepare formatted lines with values left-aligned
entries_line=$(printf "%-${label_width}s%-${value_width}s" "Entries:" "$entry_count")
updated_line=$(printf "%-${label_width}s%-${value_width}s" "Updated:" "$updated_time")
size_line=$(printf "%-${label_width}s%-${value_width}s" "Size:" "$file_size")
maintainer_line=$(printf "%-${label_width}s%-${value_width}s" "Maintainer:" "Cantue")
expires_line=$(printf "%-${label_width}s%-${value_width}s" "Expires:" "1 day (update frequency)")
license_line=$(printf "%-${label_width}s%-${value_width}s" "License:" "GPL-3.0")

# Create the description with proper alignment using a here-document
description=$(cat <<EOF
    ==================================
    $centered_title
    ---------------------------------------------
    $entries_line
    $updated_line
    $size_line
    $maintainer_line
    $expires_line
    $license_line
    ==================================
EOF
)

# Create the blocklist.txt in the required JSON format
jq -n --arg name "Adobe Blocklist" --arg description "$description" --argjson domains "$(jq -R . < $URLS_FILE | jq -s .)" '{
  name: $name,
  description: $description,
  "denied-remote-domains": $domains
}' > $BLOCKLIST_FILE

# Replace escaped newline characters with actual newlines
sed -i 's/\\n/\n/g' $BLOCKLIST_FILE

# Commit and push changes
git config --global user.name 'cyber-bot'
git config --global user.email 'github-actions@users.noreply.github.com'
commit_message="Updated blocklist ($(date -u +"%Y-%m-%d %H:%M UTC"))"
git add $BLOCKLIST_FILE $URLS_FILE
git commit -m "$commit_message"
git push $REPO_URL