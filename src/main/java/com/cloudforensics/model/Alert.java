package com.cloudforensics.model;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

public class Alert {

    private String id;
    private String timestamp;
    private String ruleName;
    private String severity;
    private String user;
    private String ip;
    private String eventType;
    private String description;

    public Alert() {}

    public Alert(String id, String timestamp, String ruleName, String severity,
                 String user, String ip, String eventType, String description) {
        this.id = id;
        this.timestamp = timestamp;
        this.ruleName = ruleName;
        this.severity = severity;
        this.user = user;
        this.ip = ip;
        this.eventType = eventType;
        this.description = description;
    }

    // =========================
    // SAFE GETTERS
    // =========================

    public String getId() {
        return id != null ? id : "UNKNOWN_ID";
    }

    public String getTimestamp() {
        return timestamp != null ? timestamp : "UNKNOWN_TIME";
    }

    public String getRuleName() {
        return ruleName != null ? ruleName : "UNKNOWN_RULE";
    }

    public String getSeverity() {
        if (severity == null) return "LOW";
        return severity.toUpperCase();
    }

    public String getUser() {
        return (user != null && !user.isEmpty()) ? user : "UNKNOWN_USER";
    }

    public String getIp() {
        return (ip != null && !ip.isEmpty()) ? ip : "UNKNOWN_IP";
    }

    public String getEventType() {
        return eventType != null ? eventType : "UNKNOWN_EVENT";
    }

    public String getDescription() {
        return description != null ? description : "No description available";
    }

    // =========================
    // OPTIONAL (FUTURE USE)
    // =========================

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Convert timestamp → LocalDateTime (for sorting if needed)
     */
    public LocalDateTime getParsedTimestamp() {
        if (timestamp == null) return LocalDateTime.MIN;

        try {
            return OffsetDateTime.parse(timestamp).toLocalDateTime();
        } catch (DateTimeParseException e) {
            return LocalDateTime.MIN;
        }
    }
}