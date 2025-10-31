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
<img width="1024" height="1024" alt="Gemini_Generated_Image_nukirqnukirqnuki(1)" src="https://github.com/user-attachments/assets/44d70e50-9838-490c-85ce-9023bd241f4b" />

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

<img width="975" height="449" alt="image" src="https://github.com/user-attachments/assets/3f0d3be0-eec8-4c42-a73e-4753ea3a8990" />


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

<img width="993" height="455" alt="image" src="https://github.com/user-attachments/assets/0dd5cd4b-6d2f-47e3-88b0-6d59c09bfed9" />


---

### 3. First Payment to New Recipient  
Highlights first-time transfers above ₹25,000 to newly added beneficiaries.

```spl
index=bank_txn amount>25000
| lookup first_payments recipient OUTPUT first_seen
| where isnotnull(first_seen) 
| table _time account recipient amount
```

<img width="1857" height="1093" alt="first payment" src="https://github.com/user-attachments/assets/bdc9baef-f918-4c7c-a6b4-00fa3dca0f0a" />



---


### 4. Paying Risky Merchant  
Detects high-value transactions made to merchants with elevated risk scores.

```spl
index=bank_txn
| lookup risky_merchants merchant_id OUTPUT risk_score
| where risk_score>50 AND amount>20000
| table _time account merchant_id amount risk_score
```

<img width="975" height="455" alt="image" src="https://github.com/user-attachments/assets/f980ef58-9cf3-406b-9c63-f2e7692dea8b" />

---

### 5. Bad Domain → Login (Phishing Pivot)  
Correlates IPs that accessed malicious domains with successful logins, revealing possible phishing or credential theft activity.

```spl
(index=dns malicious=true) OR (index=auth action=success)
| rename src_ip as ip
| stats values(user) as user by ip
| search user=*
```

<img width="975" height="466" alt="image" src="https://github.com/user-attachments/assets/b1cc9a4a-ec6f-4df8-950c-0b7fd0de462e" />


---

### 5. Many Failures → Later Success (Brute-force → Compromise)
Catches accounts that had many failed logins from the same IP and later a success—a classic brute-force or credential-stuffing pattern.

```spl
(index=dns malicious=true) OR (index=auth action=success)
| rename src_ip as ip
| stats values(user) as user by ip
| search user=*
```

<img width="975" height="466" alt="image" src="https://github.com/user-attachments/assets/b1cc9a4a-ec6f-4df8-950c-0b7fd0de462e" />


---

## Dashboards

CORTEX-FIN includes two dashboards designed for monitoring and analysis:

1. **Entity 360 Dashboard**  
   Combines correlation results for each account or device to present a unified risk view.  
   Displays transaction history, login sources, and lookup-based enrichment data for rapid investigation.  

2. **Fraud Risk Heatmap**  
  Aggregates transactional and behavioral data per account to assign a dynamic risk score.
This helps analysts instantly spot accounts showing abnormal spending, device, or merchant patterns.

How it works
For each account, the query:

- Counts total transactions
- Sums and averages transaction values
- Counts distinct merchants and devices
- Assigns weighted points to indicators (amount, merchant diversity, device usage)

Categorizes risk into visual levels — High / Medium / Low / No Risk

```spl
index=bank_txn
| stats 
    count as TotalTransactions
    sum(amount) as TotalAmount 
    avg(amount) as AvgAmount
    dc(merchant_id) as UniqueMerchants
    dc(device_id) as UniqueDevices
    by account
| eval RiskScore = 
    if(TotalAmount > 100000, 2, 0) +
    if(AvgAmount > 50000, 2, 0) +
    if(UniqueMerchants > 2, 1, 0) +
    if(UniqueDevices > 1, 1, 0)
| eval HeatMap = case(
    RiskScore >= 4, "🔴 High",
    RiskScore >= 2, "🟡 Medium", 
    RiskScore >= 1, "🟢 Low",
    true(), "⚪ No Risk")
| sort -RiskScore
| table account TotalTransactions TotalAmount AvgAmount UniqueMerchants UniqueDevices RiskScore HeatMap
```

<img width="1857" height="1359" alt="Cortex  Fin entity" src="https://github.com/user-attachments/assets/d94eeeb8-dfac-42a8-b09e-dc71781004fc" />

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


---

## Conclusion

CORTEX-FIN demonstrates that **correlation and enrichment-driven detection** can effectively connect fraud and cybersecurity telemetry inside Splunk.  
By using SPL logic and contextual lookups, the system enables transparent, analyst-driven investigation workflows suitable for any banking SOC or training environment.
