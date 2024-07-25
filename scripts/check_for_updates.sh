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

# Define the width for labels and values
label_width = 15  # width of the label field
value_width = 35  # width of the value field
line_width = max(label_width + value_width, 40)  # total line width

# Center-align the title
title = "Adobe Telemetry Blocklist"
title_padding = (line_width - len(title)) // 2
centered_title = f"{' ' * title_padding}{title}{' ' * (line_width - len(title) - title_padding)}"

# Prepare formatted lines with values left-aligned
entries_line = f"{'Entries:':<{label_width}}{entry_count:<{value_width}}"
updated_line = f"{'Updated:':<{label_width}}{updated_time:<{value_width}}"
size_line = f"{'Size:':<{label_width}}{file_size:<{value_width}}"
maintainer_line = f"{'Maintainer:':<{label_width}}{'Cantue':<{value_width}}"
expires_line = f"{'Expires:':<{label_width}}{'1 day (update frequency)':<{value_width}}"
license_line = f"{'License:':<{label_width}}{'GPL-3.0':<{value_width}}"

# Create the description with proper alignment
description=$(printf "==================================\n%s\n---------------------------------------------\n%s\n%s\n%s\n%s\n%s\n%s\n==================================" \
"$centered_title" "$entries_line" "$updated_line" "$size_line" "$maintainer_line" "$expires_line" "$license_line")

# Create the blocklist.txt in the required JSON format
jq -n --arg name "Adobe Blocklist" --arg description "$description" --argjson domains "$(jq -R . < data/urls.txt | jq -s .)" '{
  name: $name,
  description: $description,
  "denied-remote-domains": $domains
}' > data/blocklist.txt

# Commit and push changes
git config --global user.name 'cyber-bot'
git config --global user.email 'github-actions@users.noreply.github.com'
commit_message="Updated blocklist ($(date -u +"%Y-%m-%d %H:%M UTC"))"
git add data/blocklist.txt data/urls.txt previous_commit_date.txt
git commit -m "$commit_message"
git push https://x-access-token:$PAT_TOKEN@github.com/Cantue35/adobe-blocklist.git