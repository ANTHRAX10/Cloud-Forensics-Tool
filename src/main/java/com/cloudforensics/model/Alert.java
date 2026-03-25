package com.cloudforensics.model;

public class Alert {
    private String id;
    private String timestamp;
    private String ruleName;
    private String severity;
    private String user;
    private String ip;
    private String eventType;
    private String description;

    public Alert() {
    }

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

    public String getId() {
        return id;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getSeverity() {
        return severity;
    }

    public String getUser() {
        return user;
    }

    public String getIp() {
        return ip;
    }

    public String getEventType() {
        return eventType;
    }

    public String getDescription() {
        return description;
    }
}