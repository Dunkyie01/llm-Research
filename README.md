# OWASP Scrape & Check

A pair of Python scripts for collecting data from [OWASP](https://owasp.org) and checking it against your own targets. `scrape.py` pulls the data down, and `check.py` uses it.

> **Note:** Use these tools only on systems you own or have explicit permission to test.

## Contents

| File | Purpose |
| --- | --- |
| `owasp_scrape.py` | Scrapes OWASP content (e.g. Top 10 categories, descriptions, references) and saves it locally |
| `owasp_check.py` | Reads the scraped data and checks [your input, e.g. a URL / config / codebase] against it |

## Features

- Scrapes [OWASP Top 10 / Cheat Sheets / other source] into a structured format (JSON/CSV)
- Checks [headers / dependencies / code patterns / responses] against the scraped data
- Simple command-line interface
- Readable output you can save or pipe into other tools

## Requirements

- Python 3.9+
- Dependencies listed in `requirements.txt`, typically:
  - `requests`
  - `beautifulsoup4`

## Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

### 1. Scrape the data

```bash
python owasp_scrape.py
```

This writes the results to `data/owasp_data.json` (or wherever you've configured it).

### 2. Run the check

```bash
python owasp_check.py <target>
```

Example:

```bash
python owasp_check.py https://example.com
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `-o`, `--output` | Output file path | `results.json` |
| `-v`, `--verbose` | Show detailed output | off |

*(Update this table to match the arguments your scripts actually accept.)*

## Example Output

```text
[+] Loaded 10 OWASP categories
[!] A05: Security Misconfiguration - missing X-Frame-Options header
[+] A02: Cryptographic Failures - HTTPS enforced
```

## Project Structure

```text
.
├── owasp_scrape.py
├── owasp_check.py
├── requirements.txt
├── data/
│   └── owasp_data.json
└── README.md
```

## Responsible Use

Scraping should be gentle: respect OWASP's `robots.txt` and terms, avoid hammering their servers, and cache results rather than re-scraping on every run. Only run checks against targets you are authorised to test.

## Roadmap

- [ ] Add more OWASP sources
- [ ] Export results to HTML/Markdown reports
- [ ] Add unit tests
- [ ] Add CI via GitHub Actions

## Contributing

Issues and pull requests are welcome. For larger changes, please open an issue first to discuss what you'd like to change.

## License

Distributed under the MIT License. See `LICENSE` for details.

## Author

Dunkyie01 :)
