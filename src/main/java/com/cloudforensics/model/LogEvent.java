package com.cloudforensics.model;

public class LogEvent {
    private String timestamp;
    private String severity;
    private String eventType;
    private String user;
    private String resource;
    private String ip;
    private String status;

    public LogEvent() {
    }

    public LogEvent(String timestamp, String severity, String eventType, String user,
                    String resource, String ip, String status) {
        this.timestamp = timestamp;
        this.severity = severity;
        this.eventType = eventType;
        this.user = user;
        this.resource = resource;
        this.ip = ip;
        this.status = status;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}