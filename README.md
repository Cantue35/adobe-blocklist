# Little Snitch Adobe Blocklist

This repository provides a blocklist for Adobe domains formatted for use with Little Snitch. The blocklist is automatically updated and sourced from various projects.

## Sources

Current upstream lists (expanded over time):

| ID | Repository | Path | Notes |
|----|------------|------|-------|
| `a_dove` | [ignaciocastro/a-dove-is-dumb](https://github.com/ignaciocastro/a-dove-is-dumb) | `pihole.txt` | Block Adobe telemetry checking domains |
| `rudder` | [Ruddernation-Designs/Adobe-URL-Block-List](https://github.com/Ruddernation-Designs/Adobe-URL-Block-List) | `pihole.txt` | Adobe URL/IP block list |

## Usage

To use this blocklist with Little Snitch:

1. Subscribe to the rule group by copying and pasting the URL below into your browser:

   ```
   x-littlesnitch:subscribe-rules?url=https://raw.githubusercontent.com/Cantue35/adobe-blocklist/main/blocklist.lsrules
   ```

2. Little Snitch will automatically update the rules from this URL.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to suggest improvements.

## License

This project is licensed under the terms of the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.