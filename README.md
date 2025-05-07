# OctoRecon - A Workplace Browser History Analyzer

A Python script to analyze Brave browser history for workplace investigations. Generates an interactive HTML report with charts and tables categorizing browsing behavior, detecting inappropriate content, and highlighting work vs. non-work activity.

---

## Table of Contents

1. [Features](#features)  
2. [Prerequisites](#prerequisites)  
3. [Installation](#installation)  
4. [Data Acquisition](#data-acquisition)  
   - [Local Extraction](#local-extraction)  
   - [Remote Extraction (SMB)](#remote-extraction-smb)  
5. [Usage](#usage)  
6. [Examples](#examples)  
7. [Configuration & Customization](#configuration--customization)  
8. [Output](#output)  
9. [Contributing](#contributing)  
10. [License](#license)  

---

## Features

- Parses Brave `History` SQLite database and extracts URLs with timestamps  
- Categorizes visits into work, social media, streaming, shopping, gaming, news, adult, and more  
- Flags potentially inappropriate content based on keyword matching  
- Marks visits occurring within specified work days/hours  
- Generates an interactive HTML report with:
  - Executive summary  
  - Pie charts & bar plots  
  - Tables of flagged URLs  
  - Sub-tabs for non-work activity during work hours  
- Supports user-defined custom categories and work-keywords  

---

## Prerequisites

- Python 3.8+  
- A Brave `History` SQLite file (typically located in your profile directory)  
- Access to the `urls` table in the `History` database  

---

## Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/clearnetlabs/octorecon.git
   cd octorecon
   ```

2. **Create a virtual environment (optional but recommended)**  
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

   > **requirements.txt** should include:  
   > ```
   > pandas
   > matplotlib
   > seaborn
   > pytz
   > ```

---

## Data Acquisition

### Local Extraction

1. Navigate to your Brave profile directory. Common paths:

   - **macOS/Linux**:  
     ```bash
     ~/.config/BraveSoftware/Brave-Browser/Default/History
     ```
   - **Windows**:  
     ```powershell
     %USERPROFILE%\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History
     ```

2. Copy or link the `History` file and rename it (e.g., `History-BRAVE`).

3. Export the `urls` table to CSV:

   ```bash
   sqlite3 -header -csv History-BRAVE "SELECT * FROM urls;" > urls.csv
   ```

### Remote Extraction (SMB)

If you’re conducting a pentest and need to pull the `History` file over SMB:

```bash
smbclient \\\\10.10.10.1\\C$ -U 'contorso.com/username'
```

Once connected:

```bash
cd "Users/TargetUser/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default"
get History-BRAVE
exit
```

Then export to CSV as above:

```bash
sqlite3 -header -csv History-BRAVE "SELECT * FROM urls;" > urls.csv
```

---

## Usage

```bash
./octorecon.py urls.csv \
  --starttime 09:00 \
  --endtime 17:00 \
  --days M,T,W,Th,F \
  --work-keywords "mycorp.com,jira,salesforce" \
  --custom-categories "internalapp(work),companycars(auto)" \
  --output browser_history_report.html
```

### Arguments

- `csv_file`  
  Path to the CSV file exported from the Brave `urls` table.

- `--starttime` (default: `09:00`)  
  Workday start time (`"9am"`, `"09:00"`, `"13"`, etc.).

- `--endtime` (default: `17:00`)  
  Workday end time (`"5pm"`, `"17:00"`, `"17"`, etc.).

- `--days` (default: `M,T,W,Th,F`)  
  Comma-separated work days (`M`, `T`, `W`, `Th`, `F`, `Sa`, `Su`).

- `--work-keywords`  
  Comma-separated domains/keywords to force into the “work” category.

- `--custom-categories`  
  User-defined categories in the format  
  `keyword1(categoryA),keyword two(categoryB)`  

- `--output` (default: `browser_history_report.html`)  
  Name of the generated HTML report.

- `--diagnose`  
  Print diagnostic info for the first few rows and exit.

---

## Examples

1. **Basic run with defaults**  
   ```bash
   ./octorecon.py urls.csv
   ```

2. **Custom work hours and days**  
   ```bash
   ./octorecon.py urls.csv \
     --starttime 08:30 \
     --endtime 18:00 \
     --days M,T,W,Th,F,Sa
   ```

3. **Adding work keywords & custom categories**  
   ```bash
   ./octorecon.py urls.csv \
     --work-keywords "vpn.mycorp.com,docs.mycorp.com" \
     --custom-categories "internaltool(work),leasing(auto)"
   ```

---

## Configuration & Customization

- **Whitelist Domains**: Adjust `COMMON_LEGIT_DOMAINS_WHITELIST` in the script.  
- **Category Patterns**: Modify the `self.patterns` dictionary for additional domains/patterns.  
- **Inappropriate Keywords**: Edit the `self.inappropriate_keywords` set to tune sensitivity.  
- **Charts & Styling**: Tweak `matplotlib`/`seaborn` settings in `generate_report()`.

---

## Output

- **HTML Report**: Interactive file showing summary, visuals, and tables.  
- **Charts PNG**: Saved as `browser_analysis_charts.png` alongside the report.

---

## Contributing

1. Fork the repo.  
2. Create a branch:  
   ```bash
   git checkout -b feature/<your-feature>
   ```  
3. Make your changes & add tests.  
4. Submit a Pull Request describing your enhancements.  

Please follow the existing code style and include documentation for any new features.

---

## License

This project is licensed under the Apache2.0 License. See [LICENSE](./LICENSE) for details.  

