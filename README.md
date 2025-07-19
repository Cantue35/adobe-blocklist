<p align="center">
  <a href="https://github.com/Cantue35/adobe-blocklist" target="_blank">
    <img src="https://raw.githubusercontent.com/Cantue35/adobe-blocklist/main/data/blocklistbanner.png" width="425px" alt="Adobe Blocklist for Little Snitch banner">
  </a>
</p>

<p align="center">
  <a href="https://github.com/Cantue35/adobe-blocklist/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Cantue35/adobe-blocklist" alt="license">
  </a>
  <a href="https://github.com/Cantue35/adobe-blocklist/commits/main">
    <img src="https://img.shields.io/github/last-commit/Cantue35/adobe-blocklist" alt="last commit">
  </a>
  <a href="https://github.com/Cantue35/adobe-blocklist/commits/main">
    <img src="https://img.shields.io/github/commit-activity/m/Cantue35/adobe-blocklist" alt="commit activity">
  </a>
</p>

This repository provides a curated blocklist of Adobe-related domains, formatted for use with [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html). The list is automatically updated, built from multiple upstream sources, and compiled into native `.lsrules` format.

---

### 🌐 Sources

| ID       | Repository                                                                 | Path         | Notes                                     |
|----------|----------------------------------------------------------------------------|--------------|-------------------------------------------|
| `a_dove` | [ignaciocastro/a-dove-is-dumb](https://github.com/ignaciocastro/a-dove-is-dumb) | `pihole.txt` | Blocks Adobe telemetry domains            |
| `rudder` | [Ruddernation-Designs/Adobe-URL-Block-List](https://github.com/Ruddernation-Designs/Adobe-URL-Block-List) | `pihole.txt` | General Adobe URL/IP blocklist            |

<p align="left"><i>
This list will expand over time as new, reputable sources are added.  
Have a suggestion? Feel free to <a href="https://github.com/Cantue35/adobe-blocklist/issues">open an issue</a>.
</i></p>

---

### ⚙️ Usage

To subscribe in Little Snitch:

1. Paste the following link into your browser:

   ```
   x-littlesnitch:subscribe-rules?url=https://raw.githubusercontent.com/Cantue35/adobe-blocklist/main/blocklist.lsrules
   ```

2. Little Snitch will open and prompt you to subscribe.

---

### 🛠 Contributing

Found a missed domain, false positive, or a helpful upstream source?  
[Open an issue](https://github.com/Cantue35/adobe-blocklist/issues) or submit a pull request — contributions are welcome!

---

### 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
