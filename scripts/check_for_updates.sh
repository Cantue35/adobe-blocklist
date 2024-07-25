#!/bin/bash

# Fetch the latest commit date for pihole.txt
latest_commit_date=$(curl -s https://api.github.com/repos/ignaciocastro/a-dove-is-dumb/commits?path=pihole.txt | jq -r '.[0].commit.committer.date')

# Load the previous commit date from a file
if [ -f previous_commit_date.txt ]; then
  previous_commit_date=$(cat previous_commit_date.txt)
else
  previous_commit_date=""
fi

# Compare dates
if [ "$latest_commit_date" == "$previous_commit_date" ]; then
  echo "No updates found."
  exit 0
else
  echo "Updates found."
  echo "$latest_commit_date" > previous_commit_date.txt
fi

# Fetch the latest pihole.txt
curl -o data/pihole.txt https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/main/pihole.txt

# Process the blocklist: remove comments, reverse domain components, sort, and reverse back
grep -v '^#' data/pihole.txt | awk -F. '{OFS="."; for(i=NF; i>0; i--) printf("%s%s", $i, (i>1?OFS:ORS))}' | sort | awk -F. '{OFS="."; for(i=NF; i>0; i--) printf("%s%s", $i, (i>1?OFS:ORS))}' > data/urls.txt

# Count entries
entry_count=$(wc -l < data/urls.txt)

# Get file size
file_size=$(du -h data/urls.txt | cut -f1)

# Get current date and time in UTC
updated_time=$(date -u +"%b %d, %Y, %I:%M %p (UTC)")

# Create the blocklist.txt in the required JSON format
{
  echo '{'
  echo '  "name": "Adobe Blocklist",'
  echo '  "description": "==================================\\n                  Adobe Telemetry Blocklist\\n---------------------------------------------\\nEntries:         '"$entry_count"'\\nUpdated:      '"$updated_time"'\\nSize:             '"$file_size"'\\nMaintainer:   Cantue\\nExpires:        1 day (update frequency)\\nLicense:       GPL-3.0\\n==================================",'
  echo '  "denied-remote-domains": ['
  while read -r domain; do
    echo "    \"$domain\","
  done < data/urls.txt
  echo "  ]"
  echo "}"
} > data/blocklist.txt

# Remove the last comma from the JSON array
sed -i '$s/,$//' data/blocklist.txt

# Commit and push changes
git config --global user.name 'github-actions'
git config --global user.email 'github-actions@users.noreply.github.com'
commit_message="Updated blocklist ($(date -u +"%Y-%m-%d %H:%M UTC"))"
git add data/blocklist.txt data/urls.txt previous_commit_date.txt
git commit -m "$commit_message"
git push