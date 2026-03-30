# Cloud Forensics Investigation Tool
## Project Overview

The **Cloud Forensics Investigation Tool** is a centralized Digital Forensics & Incident Response (DFIR) platform designed to simulate modern enterprise-grade Security Operations Center (SOC) environments. The system processes, normalizes, and analyzes cloud activity logs (e.g., from AWS, Azure, Google Cloud) to detect, correlate, and investigate security incidents and malicious activities.

By automating the ingestion of heterogeneous logs and providing an interactive dashboard, the tool enables security teams to quickly reconstruct attack timelines, preserve evidence, and map behaviors to known threat models (like MITRE ATT&CK).

### Core Features

*   **Log Ingestion & Parsing**: Pulls in logs from various cloud providers (CloudTrail, Activity Logs, Audit Logs) and normalizes them into a unified forensic schema.
*   **Real-time Dashboard**: A sleek, dark-themed SOC dashboard providing a high-level view of ingested logs, active alerts, and correlated cases.
*   **Anomaly Detection (Alerts)**: Identifies unauthorized logins, bulk downloads, suspicious geographic activity, and other indicators of compromise (IoC).
*   **Event Correlation**: Automatically groups related individual alerts into broader **Incident Cases** to highlight advanced persistent threats or multi-stage attacks.
*   **Evidence Preservation**: Secures log integrity using cryptographic hashing (SHA-256) and stores artifacts in a tamper-evident evidence locker.
*   **Attack Timeline Reconstruction**: Visually reconstructs the chronological sequence of an attack based on correlated events.
*   **Forensic Reporting**: Generates automated technical and executive summaries for post-incident reviews.

---

## Technology Stack

The project utilizes a split-stack architecture consisting of a robust Java Spring Boot backend and a vanilla web frontend. 

### Backend
*   **Language**: Java 17
*   **Framework**: Spring Boot 3.1.3
*   **Core Modules**:
    *   `spring-boot-starter-web`: Provides the embedded Tomcat server and enables the creation of RESTful APIs to serve data to the frontend.
    *   `spring-boot-starter-test`: For backend unit and integration testing.
*   **Utilities**: Lombok (for reducing boilerplate code such as getters, setters, and constructors).
*   **Build Tool**: Maven

### Frontend (SOC Dashboard)
*   **Structure**: HTML5
*   **Styling**: Pure Vanilla CSS3
    *   Utilizes modern CSS layout techniques including Flexbox and CSS Grid.
    *   Implements a custom dark-mode design system with centralized CSS variables for colors, borders, and typography (`:root` variables).
    *   Fully responsive, highly polished dashboard mimicking professional DFIR platforms.
*   **Logic & Integration**: Vanilla JavaScript (ES6)
    *   Asynchronous integration with backend Spring Boot APIs using the modern browser `fetch` API.
    *   Dynamic DOM manipulation for real-time rendering of Logs, Alerts, and Cases.
    *   Automatic polling feature for live dashboard updates.
*   **Typography**: Google Fonts ('Inter' - clean, sans-serif optimal for data-heavy interfaces).
*   **Iconography**: FontAwesome 6.4 (Used extensively for sidebar navigation, status indicators, and metric cards).
