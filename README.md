# 🔎 Incident Investigation

## Phase 1 – Reconnaissance & Attacker Identification

### Objective

Identify the source of suspicious traffic targeting the web server.

### SPL Query

```spl
index=botsv1 sourcetype="stream:http"
| stats count by src_ip
| sort - count
```

### Findings

Analysis of HTTP traffic revealed a single external IP generating an abnormally large volume of requests.

**Primary IOC**

```text
40.80.148.42
```

This IP address was identified as the primary threat actor and became the focus of the investigation.

### Evidence

<p align="center">
  <img width="1906" height="749" alt="LFI Exploitation Evidence" src="https://github.com/user-attachments/assets/27d5cc5b-422f-4be1-be80-b362def7eb83" />
</p>

The evidence above demonstrates abnormal activity originating from the identified source IP address.

---

## Phase 2 – Vulnerability Scanning & Local File Inclusion

### Objective

Determine how the attacker gained initial access to the target system.

### SPL Query

```spl
index=botsv1 src_ip="40.80.148.42" sourcetype="stream:http"
(uri="*/windows/win.ini*" OR uri="*boot.ini*")
| table uri status
```

### Findings

The attacker used the Acunetix Vulnerability Scanner to identify vulnerabilities within the Joomla application.

Directory traversal payloads were successfully executed, allowing access to sensitive system files.

Example payload:

```text
..%5C/..%5C/..%5C/..%5C/windows/win.ini
```

The HTTP 200 response confirmed successful exploitation.

### Evidence

<p align="center">
  <img width="1906" height="749" alt="LFI Exploitation Evidence" src="https://github.com/user-attachments/assets/27d5cc5b-422f-4be1-be80-b362def7eb83" />
</p>

The screenshot shows successful access to system files through directory traversal techniques. The HTTP status code 200 confirms the requested file was retrieved successfully.

---

## Phase 3 – Credential Access (Brute Force Attack)

### Objective

Determine whether administrator credentials were compromised.

### SPL Query

```spl
index=botsv1 src_ip="40.80.148.42"
sourcetype="stream:http"
uri="/joomla/administrator/index.php"
http_method="POST"
| table _time status client_ip uri
| sort _time
```

### Findings

The attacker launched a brute-force attack against the Joomla administrator login portal.

At 2016-08-11 03:18:05 UTC, the response changed from HTTP 200 to HTTP 303.

This response pattern indicates successful authentication and confirms compromise of an administrator account.

### Evidence

<p align="center">
  <img width="1489" height="712" alt="Successful Joomla Administrator Login" src="https://github.com/user-attachments/assets/dd60889f-40c7-4d47-8ac5-46b046280afa" />
</p>

The screenshot shows the transition from HTTP 200 responses to HTTP 303 redirects, confirming successful authentication to the Joomla administrator dashboard.

---

## Phase 4 – Persistence & Web Shell Deployment

### Objective

Identify post-compromise persistence mechanisms.

### SPL Query

```spl
index=botsv1 src_ip="40.80.148.42"
sourcetype="stream:http"
uri="*.php*"
NOT uri="*index.php*"
NOT uri="*search*"
| stats count by uri
```

### Findings

After obtaining administrator access, the attacker uploaded malicious PHP files to establish persistence.

The investigation identified two web shells:

```text
/2WMuthHKyu.php

/ZAk5LbgaGf.php
```

These files provided Remote Code Execution (RCE) capabilities and allowed continued access to the compromised server.

### Evidence

<p align="center">
  <img width="1783" height="682" alt="Web Shell Discovery Evidence" src="https://github.com/user-attachments/assets/d8d7ce0e-5426-4eab-b426-d4fedafe3fd4" />
</p>

The screenshot highlights the malicious PHP files uploaded by the attacker. These files function as web shells and provide persistent access to the compromised environment.

---

# 📌 Key Indicators of Compromise (IOCs)

| IOC Type     | Value           |
| ------------ | --------------- |
| Attacker IP  | 40.80.148.42    |
| Scanner      | Acunetix        |
| Target Host  | demo-01         |
| CMS Platform | Joomla          |
| Web Shell    | /2WMuthHKyu.php |
| Web Shell    | /ZAk5LbgaGf.php |

---

# 🛡️ MITRE ATT&CK Mapping

| Tactic              | Technique                            | ATT&CK ID |
| ------------------- | ------------------------------------ | --------- |
| Reconnaissance      | Active Scanning                      | T1595     |
| Initial Access      | Exploit Public-Facing Application    | T1190     |
| Credential Access   | Brute Force                          | T1110     |
| Persistence         | Server Software Component: Web Shell | T1505.003 |
| Command and Control | Web Shell                            | T1505.003 |

---

# 📝 Conclusion

The investigation confirmed that threat actor 40.80.148.42 successfully compromised the Joomla web server through vulnerability scanning, Local File Inclusion (LFI) exploitation, credential brute forcing, and web shell deployment.

The attacker ultimately achieved persistent Remote Code Execution (RCE) by uploading malicious PHP web shells to the server.

This investigation demonstrates practical experience in:

* Threat Hunting
* Incident Response
* Splunk SPL Querying
* IOC Identification
* Web Application Security
* Security Monitoring
* Blue Team Operations
