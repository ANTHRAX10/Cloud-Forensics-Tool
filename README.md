☁️ Cloud Forensics Investigation Tool

🔍 A Java-based Digital Forensics & Incident Response (DFIR) system that analyzes simulated cloud activity logs to investigate security incidents across AWS, Azure, and Google Cloud environments.

This tool mimics real-world cloud breach investigation platforms used by SOC teams to detect malicious activity, reconstruct attack timelines, preserve digital evidence, and generate forensic reports.

🚀 Features

✨ Log Ingestion
Load and process simulated cloud logs (CloudTrail, activity logs, audit logs)

🧩 Log Parsing & Normalization
Convert heterogeneous logs into a unified forensic schema

🚨 Suspicious Activity Detection
Identify anomalies such as:

Unauthorized logins
Privilege escalation
API abuse
Bulk data downloads
Suspicious VM activity
Data exfiltration patterns

🔗 Event Correlation Engine
Link related events across services to build attack narratives

⏱️ Timeline Reconstruction
Generate a chronological sequence of attacker actions

🛡️ Evidence Integrity
Protect logs using SHA-256 hashing to detect tampering

📊 Forensic Report Generation
Produce structured investigation summaries and findings

🔎 Search & Query Support
Filter logs by user, IP address, time range, or event type

🧠 Use Cases
Cloud breach investigation
Insider threat analysis
Account takeover investigation
Security research & education
Incident response training
🛠️ Tech Stack
Language: Java
Log Format: JSON
Database: MySQL / MongoDB (optional)
Parsing: Jackson / Gson
Security: SHA-256 hashing
UI: JavaFX (optional)
⚙️ How It Works

1️⃣ Load cloud log files
2️⃣ Parse and normalize data
3️⃣ Store evidence securely
4️⃣ Detect suspicious behavior
5️⃣ Correlate related events
6️⃣ Build attack timeline
7️⃣ Generate forensic report

🎯 Project Goal

To simulate enterprise-grade cloud forensic investigation tools used by Security Operations Centers (SOC) and incident response teams for analyzing post-incident cloud activity and reconstructing attack scenarios.

🏆 Why This Project Matters

Cloud environments generate massive distributed logs that are difficult to analyze manually.
This tool demonstrates automated investigation techniques essential for modern cloud security and digital forensics.

📌 Future Enhancements
Machine learning–based anomaly detection
Interactive dashboard & visual analytics
Geo-location mapping of login activity
Multi-case investigation support
