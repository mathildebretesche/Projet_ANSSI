

# 🛡️ Vulnerability Monitoring & Alerting System

This project is an automated security intelligence tool designed to scrape alerts from **ANSSI** (the French National Cybersecurity Agency), enrich them with technical data from global sources like **MITRE** and **FIRST**, and dispatch targeted email notifications to subscribers based on their specific technology stack.

## 🏗️ Project Architecture

The application follows a four-stage pipeline to transform raw security bulletins into actionable intelligence:

1. **Data Extraction:** Automated scraping of the CERT-FR portal.
2. **Data Enrichment:** Querying external APIs for technical metrics (CVSS, CWE, EPSS).
3. **Data Consolidation:** Cleaning and structuring data using Pandas.
4. **Alerting & Notification:** Intelligence-driven email dispatch for critical threats.

---

## 🔍 Data Extraction (ANSSI Scraping)

The script targets the **ANSSI Alerte** webpage. It parses the HTML to find links to specific security bulletins.

* **Method:** For each bulletin, the script accesses its JSON representation directly.
* **CVE Identification:** A Regex-based pattern-matching engine scans the bulletin content to extract all associated **CVE IDs** (Common Vulnerabilities and Exposures).
* **Persistence:** To optimize performance, the system maintains a **processed_cves.json** file. It checks this file before processing a CVE to ensure that duplicates are not re-analyzed in subsequent runs.

---

## 🚀 Data Enrichment (API Integration)

Once a new CVE is identified, the system enriches the entry by communicating with two major cybersecurity databases:

### **MITRE API (CVE AWG)**

* **CVSS Score:** Retrieves the Base Score to determine theoretical danger.
* **CWE (Common Weakness Enumeration):** Identifies the type of software flaw (e.g., Buffer Overflow, SQL Injection).
* **Affected Scope:** Extracts the specific Vendor, Product name, and Version strings impacted by the vulnerability.

### **FIRST API (EPSS)**

* **Exploit Prediction:** Retrieves the **EPSS score**, which represents the probability (0 to 1) that the vulnerability will be exploited in the wild within the next 30 days. This allows for risk-based prioritization rather than just severity-based.

---

## 📊 Data Consolidation (Pandas)

All extracted and enriched data is gathered into a **Pandas DataFrame**. This stage ensures data integrity and portability:

* **Cleaning:** The system removes tabulations, newlines, and redundant whitespaces to ensure the final report is readable.
* **Severity Mapping:** A custom function maps numerical CVSS scores to qualitative categories: **Low, Medium, High, or Critical**.
* **Export:** The final consolidated dataset is saved as **donnees_consolidees.csv**, which serves as a master record for auditing or further analysis in tools like Excel or Jupyter Notebook.

---

## 📧 Alerting & Email Notification System

The final phase of the script is an intelligent notification engine located in the **main.py** file. It ensures that the right information reaches the right person.

### **Subscription Logic**

The system uses a **Subscription Dictionary** where users are mapped to specific keywords (e.g., "Fortinet", "Cisco", "SharePoint").

* **Filtering:** The engine only processes vulnerabilities marked as **Critical**.
* **Matching:** For every critical CVE, the script compares the **Vendor**, **Product**, and **ANSSI Title** against the user's subscription list.

### **SMTP Implementation**

The system utilizes the **smtplib** and **email.mime** libraries to deliver alerts:

* **Security:** It uses **STARTTLS** for encrypted communication with the Gmail SMTP server.
* **Automation:** If a match is found, a detailed email is generated automatically, containing the CVE ID, a technical description, the CVSS/EPSS scores, and the direct link to the ANSSI alert.
* **Unidentified Threats:** A fallback mechanism exists for "Unknown" vendors, ensuring that critical alerts without a clear editor are still sent to a general security administrator.

---

## 📈 Visual Demonstration (Jupyter Notebook)

The accompanying video demonstrates the execution of a **Jupyter Notebook** that visualizes the collected data.

* **Severity Distribution:** Graphical representation of the threat landscape.
* **Top Affected Vendors:** Identification of which software editors are currently most vulnerable.
* **CWE Analysis:** Pie charts showing the most common types of vulnerabilities (e.g., CWE-89 for SQL Injection).

---

## 🛠️ Setup and Execution

### **Prerequisites**

* Python 3.8 or higher.
* Required Libraries: **requests, pandas, smtplib, matplotlib, seaborn**.

### **Configuration**

To enable email alerts, update the **send_email** function in **main.py** with a valid Gmail App Password.

### **Run the Analysis**

Run the following command to start the full pipeline:
`python main.py`

