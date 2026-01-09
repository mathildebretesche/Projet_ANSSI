# ANSSI Advisories & Alerts Analysis and CVE Enrichment

This project automates cybersecurity monitoring by processing ANSSI (CERT-FR) bulletins. It extracts vulnerabilities, enriches them with global criticality data, and generates visual analyses for risk management.

---

## 📋 Project Overview

In a context of increasing cyber threats, rapid identification of vulnerabilities is crucial. This script addresses the lack of automation in ANSSI RSS feeds by transforming textual bulletins into structured, enriched data.

### Main Objectives:
- **Automated Collection:** Extract advisories and alerts from the CERT-FR RSS feed.
- **Smart Extraction:** Identify CVE codes using official JSON files and regular expressions (Regex).
- **Data Enrichment:** Retrieve severity scores (CVSS) and vulnerability types (CWE) via the MITRE API, as well as exploitation probability via the EPSS API (FIRST).
- **Analysis & Prioritization:** Create a visual dashboard to identify urgent issues.

---

## 🛠️ Installation & Prerequisites

### Prerequisites
- Python 3.10 or higher.
- Internet connection (for API calls).

### Installing Libraries
Use the following command to install the required dependencies:

```bash
pip install requests feedparser pandas matplotlib seaborn
```

---

## 🚀 How the Code Works
### The project is divided into several key steps integrated into the pipeline:

- **Extraction** (Steps 1 & 2): The script parses the RSS feed and downloads the JSON versions of ANSSI bulletins to list CVEs.
- **Enrichment** (Step 3): For each CVE, the script queries:

- **MITRE API**: To obtain the CVSS score (0-10), description, and affected product.
- **EPSS API**: To obtain the exploitation probability score (0-1).

- **Consolidation** (Step 4): Data is cleaned and grouped into a file named donnees_consolidees.csv. If an ANSSI alert contains 10 CVEs, it will be repeated over 10 rows for granular analysis.
- **Visualization** (Step 5): A Jupyter Notebook is used to generate charts (histograms, CVSS/EPSS scatter plots, pie charts).
- **Alerting** (Step 6): Automatic email notification if a critical vulnerability is detected on a monitored product.




*Important Note: The script respects a 2-second delay between API requests to avoid overloading external servers (rate limiting).*

