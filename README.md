# Comprehensive SOC Investigation Report: Splunk BOTS v1
**Project Title:** Threat Hunting & Incident Response with Splunk (Boss of the SOC v1)  
**Analyst:** SOC Analyst / Blue Team Engineer  
**Environment:** Kali Linux, Splunk Enterprise  
**Target Organization:** Wayne Enterprises (Fictional target for BOTS dataset)  

---

## 1. Project Overview
The objective of this project was to deploy a local instance of Splunk Enterprise on Kali Linux, ingest the official Splunk Boss of the SOC (BOTS) Version 1 dataset, and conduct a full-scale threat hunting investigation. The investigation tracks an Advanced Persistent Threat (APT) from initial reconnaissance to the deployment of persistent web shells on a public-facing Joomla web server.

---

## 2. Lab Setup & Data Ingestion
To recreate a realistic Security Operations Center (SOC) environment, I configured Splunk locally and manually ingested the attack-only dataset.

### Step-by-Step Configuration:
1. **Downloading the Dataset:** The dataset was downloaded from the official Splunk GitHub repository using the web browser to bypass large-file terminal restrictions.
2. **Deploying the Data to Splunk:**
   The compressed file was moved into the Splunk applications directory and extracted to automatically configure the pre-indexed data.
   ```bash
   sudo mv ~/Downloads/botsv1-attack-only.tgz /opt/splunk/etc/apps/
   cd /opt/splunk/etc/apps/
   sudo tar -xvf botsv1-attack-only.tgz
   ```
  

3. **Restarting the Splunk Service:**
   ```bash
   cd /opt/splunk/bin
   sudo ./splunk restart --run-as-root
   ```
4. **Validating Ingestion:**
   Searched Splunk using `index=botsv1` with the Time Range set to **"All Time"** (Historical), successfully validating the ingestion of over 955,000 security events.

---

## 3. Incident Investigation: Web Server Compromise

### Phase 1: Reconnaissance & Attacker Identification
The investigation began by identifying the source of anomalous traffic targeting the web server (`demo-01`). By analyzing HTTP stream logs, I isolated the highest volume of requests.

* **SPL Query:**
  ```splunk
  index=botsv1 sourcetype="stream:http" 
  | stats count by src_ip 
  | sort - count
  ```
* **Finding:** The external IP address **`40.80.148.42`** generated an abnormal amount of traffic, confirming it as the primary Indicator of Compromise (IOC).

### Phase 2: Vulnerability Scanning & Local File Inclusion (LFI)
Next, I investigated the attacker's HTTP requests to uncover their tooling and intent. The attacker attempted to mask their identity using a spoofed User-Agent (Chrome 41 on Windows 7). However, deep log analysis revealed their true tool was the **Acunetix Vulnerability Scanner**.

The attacker discovered and exploited a Local File Inclusion (LFI) / Directory Traversal vulnerability.
* **SPL Query:**
  ```splunk
  index=botsv1 src_ip="40.80.148.42" sourcetype="stream:http" (uri="*/windows/win.ini*" OR uri="*boot.ini*")
  | table uri, status
  ```
* **Finding:** The attacker injected directory traversal payloads (e.g., `..%5C/..%5C/..%5C/..%5C/windows/win.ini`). The server responded with an HTTP **`200 OK`** status code, meaning the system configuration files were successfully exposed to the attacker.
 <img width="1906" height="749" alt="Screenshot 2026-06-01 130306" src="https://github.com/user-attachments/assets/27d5cc5b-422f-4be1-be80-b362def7eb83" />

### Phase 3: Credential Access (Brute Force Attack)
Unable to gain complete control via LFI, the attacker shifted tactics to an aggressive brute-force attack against the Joomla administrator panel.

* **SPL Query:**
  ```splunk
  index=botsv1 src_ip="40.80.148.42" sourcetype="stream:http" uri="/joomla/administrator/index.php" http_method="POST"
  | table _time, status, client_ip, uri
  | sort _time
  ```
* **Finding:** At exactly **2016-08-11 03:18:05 UTC**, the server response shifted from a `200` (Failed Login) to a **`303 See Other`** redirect. In Joomla, this specific redirect confirms that the attacker successfully cracked the administrator password and gained access to the backend dashboard.*

<img width="1489" height="712" alt="Screenshot 2026-06-01 130621" src="https://github.com/user-attachments/assets/dd60889f-40c7-4d47-8ac5-46b046280afa" />
 

### Phase 4: Persistence & Web Shell Deployment
With administrative access secured, the attacker utilized a vulnerable third-party extension (`php-ofc-library`) to upload malicious payloads and establish permanent remote control (RCE).

* **SPL Query:**
  ```splunk
  index=botsv1 src_ip="40.80.148.42" sourcetype="stream:http" uri="*.php*" NOT uri="*index.php*" NOT uri="*search*"
  | stats count by uri
  ```
* **Finding:** By filtering out normal Joomla traffic and focusing on newly created standalone `.php` files, I discovered two persistent Web Shells planted in the root directory:
  1. `/2WMuthHKyu.php`
  2. `/ZAk5LbgaGf.php`
<img width="1783" height="682" alt="Screenshot 2026-06-01 132333" src="https://github.com/user-attachments/assets/d8d7ce0e-5426-4eab-b426-d4fedafe3fd4" />

---

## 4. Conclusion & Incident Summary
The threat actor (IP: `40.80.148.42`) successfully compromised the Wayne Enterprises web server through a sequence of automated scanning, LFI exploitation, and administrative brute-forcing. The breach resulted in the deployment of two hidden PHP web shells, granting the attacker full Remote Code Execution (RCE) capabilities.

### Recommended Remediation Steps:
1. **Containment:** Immediately isolate the compromised server (`demo-01`) from the production network.
2. **Eradication:** Delete the identified web shells (`/2WMuthHKyu.php` and `/ZAk5LbgaGf.php`). Revoke all active sessions and force a global password reset for all administrative accounts.
3. **Hardening:** Patch the base Joomla installation, remove the vulnerable `php-ofc-library` plugin, and deploy a Web Application Firewall (WAF) to block directory traversal payloads and limit login attempts.
