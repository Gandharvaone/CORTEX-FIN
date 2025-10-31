# CORTEX-FIN — Correlation & Threat Exchange for Finance (Splunk)

## Overview

**CORTEX-FIN** is a Splunk-based fraud and threat correlation system built for financial security operations.  
It unifies **banking transaction data**, **authentication logs**, and **DNS telemetry** to identify suspicious activity that may indicate fraud or compromise.  

The project showcases how **rule-based correlation and contextual enrichment** can provide deep visibility into financial risks — without using any external AI or ML components.  
CORTEX-FIN demonstrates a realistic SOC workflow for detecting fraud patterns, credential abuse, and phishing-driven account takeovers within Splunk.

---

## Objective

| Goal | Description |
|------|--------------|
| **Purpose** | Detect correlated fraud and cyber threats through Splunk correlation logic. |
| **Concept** | Integrate transaction, login, and DNS data with contextual lookups for entity-level risk analysis. |
| **Outcome** | Generate explainable, rule-based alerts that help analysts investigate faster. |
| **Technology Stack** | Splunk Free Instance (Home Lab) · Windows 11 · CSV Lookups · Simple XML Dashboards |

---

## Architecture Overview

```
       +------------------+
       | bank_txn (Fraud) |
       +------------------+
                │
   +----------------------------+
   | Lookups:                  |
   | - trusted_devices.csv     |
   | - risky_merchants.csv     |
   | - new_devices.csv         |
   | - first_payments.csv      |
   +----------------------------+
                │
      +------------------+       +------------------+
      | auth (Logins)    |       | dns (Threat Feed)|
      +------------------+       +------------------+
                │                   │
                └──────► CORTEX-FIN Correlation Engine ◄──────┘
                              │
                              ▼
                 Entity 360 Dashboard / Fraud Risk Heatmap
```

> *Screenshot placeholder:* `diagrams/cortexfin_architecture.png`

---

## Data and Folder Structure

```
CORTEX-FIN/
├── README.md
├── data/
│   ├── bank_txn.csv
│   ├── login_logs.csv
│   └── dns_logs.csv
├── lookups/
│   ├── risky_merchants.csv
│   ├── trusted_devices.csv
│   ├── new_devices.csv
│   └── first_payments.csv
├── spl/
│   └── correlation_rules.spl
└── dashboards/
    └── entity_360.xml
```

> *Screenshot placeholder:* `screenshots/lookup_config.png`

---

## Environment Setup

1. Install and launch **Splunk Free Instance (Local)** on Windows 11.  
2. Create the following indexes:
   - `bank_txn`
   - `auth`
   - `dns`
3. Upload each dataset CSV to its respective index.  
4. Add lookup files under **Settings → Lookups → Lookup Table Files → Add New**.  
5. Set permission scope to **Shared in App**.  
6. Verify lookup import:
   ```spl
   | inputlookup risky_merchants.csv | head 5
   ```

---

## Correlation Rules (SPL)

Each SPL rule identifies a different financial or threat behavior pattern.  
These can be saved as scheduled searches or correlation alerts inside Splunk.

---

### 1. Triple-First — New Device + New Merchant + High Amount  
Detects large transactions from newly seen devices and merchants.

```spl
index=bank_txn amount>100000
| lookup trusted_devices device_id OUTPUT trusted
| lookup merchant_list merchant_id OUTPUT category
| lookup new_devices device_id OUTPUT new_device
| where isnull(trusted) AND isnull(category) AND new_device=1
| table _time account user device_id merchant_id amount
```

> *Screenshot placeholder:* `screenshots/triple_first_output.png`

---

### 2. Many Small Payments in 5 Minutes  
Identifies multiple small transfers in a short period that add up to a large total.

```spl
index=bank_txn
| bin _time span=5m
| stats count as transactions sum(amount) as total by account _time
| where transactions>=5 AND total>100000
| table _time account transactions total
```

> *Screenshot placeholder:* `screenshots/txn_burst_panel.png`

---

### 3. First Payment to New Recipient  
Highlights first-time transfers above ₹25,000 to newly added beneficiaries.

```spl
index=bank_txn amount>25000
| lookup first_payments recipient OUTPUT first_seen
| where isnotnull(first_seen)
| table _time account recipient amount
```

> *Screenshot placeholder:* `screenshots/first_payment_output.png`

---

### 4. Paying Risky Merchant  
Detects high-value transactions made to merchants with elevated risk scores.

```spl
index=bank_txn
| lookup risky_merchants merchant_id OUTPUT risk_score
| where risk_score>50 AND amount>20000
| table _time account merchant_id amount risk_score
```

> *Screenshot placeholder:* `screenshots/risky_merchants_output.png`

---

### 5. Bad Domain → Login (Phishing Pivot)  
Correlates IPs that accessed malicious domains with successful logins, revealing possible phishing or credential theft activity.

```spl
(index=dns malicious=true) OR (index=auth action=success)
| rename src_ip as ip
| stats values(user) as user by ip
| search user=*
```

> *Screenshot placeholder:* `screenshots/phishing_pivot_panel.png`

---

## Dashboards

CORTEX-FIN includes two dashboards designed for monitoring and analysis:

1. **Entity 360 Dashboard**  
   Combines correlation results for each account or device to present a unified risk view.  
   Displays transaction history, login sources, and lookup-based enrichment data for rapid investigation.  

   *Screenshot placeholder:* `screenshots/entity_360_dashboard.png`

2. **Fraud Risk Heatmap**  
   Visualizes aggregate fraud and threat activity across all entities.  
   Highlights high-risk accounts, merchants, and devices based on correlation rule hits and severity.  

   *Screenshot placeholder:* `screenshots/fraud_heatmap.png`

---

## Analyst Workflow

1. Execute all correlation searches and save as reports.  
2. Review correlation results within the dashboards.  
3. Investigate entities that trigger multiple rules.  
4. Validate findings and escalate high-risk alerts to relevant teams.  

> *Screenshot placeholder:* `screenshots/dashboard_summary.png`

---

## Security Notes

- All data used in CORTEX-FIN is **synthetic** and anonymized for educational purposes.  
- No real banking or customer data is used.  
- The project runs entirely in a **local Splunk home-lab** environment.  

---

## Results

| Metric | Observation |
|---------|--------------|
| **High-Risk Alerts** | ~12 transactions flagged across 5 accounts |
| **False Positive Rate** | < 10% after lookup enrichment |
| **Detection Accuracy** | ~90% for simulated scenarios |

> *Screenshot placeholder:* `screenshots/results_summary.png`

---

## Conclusion

CORTEX-FIN demonstrates that **correlation and enrichment-driven detection** can effectively connect fraud and cybersecurity telemetry inside Splunk.  
By using simple SPL logic and contextual lookups, the system enables transparent, analyst-driven investigation workflows suitable for any banking SOC or training environment.

---

## Repository Layout

```
CORTEX-FIN/
├── README.md
├── diagrams/
│   └── cortexfin_architecture.png
├── screenshots/
│   ├── triple_first_output.png
│   ├── txn_burst_panel.png
│   ├── first_payment_output.png
│   ├── risky_merchants_output.png
│   ├── phishing_pivot_panel.png
│   ├── entity_360_dashboard.png
│   ├── fraud_heatmap.png
│   └── results_summary.png
├── data/
│   ├── bank_txn.csv
│   ├── login_logs.csv
│   └── dns_logs.csv
├── lookups/
│   ├── risky_merchants.csv
│   ├── trusted_devices.csv
│   ├── new_devices.csv
│   └── first_payments.csv
└── spl/
    └── correlation_rules.spl
```

---

**Author:** Gandharva  
**Category:** Banking SOC / Fraud & Threat Correlation  
**Environment:** Splunk Free Instance (Home Lab) · Windows 11  
**Date:** October 2025  
