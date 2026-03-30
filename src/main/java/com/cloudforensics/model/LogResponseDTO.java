package com.cloudforensics.model;

/**
 * Maintains backward compatibility with the frontend by exposing flattened fields.
 */
public class LogResponseDTO {
    private String timestamp;
    private String severity;
    private String eventType;
    private String user;
    private String resource;
    private String ip;
    private String status;
    private String detectionReason;

    public LogResponseDTO() {
    }

    public LogResponseDTO(String timestamp, String severity, String eventType, String user,
                          String resource, String ip, String status, String detectionReason) {
        this.timestamp = timestamp;
        this.severity = severity;
        this.eventType = eventType;
        this.user = user;
        this.resource = resource;
        this.ip = ip;
        this.status = status;
        this.detectionReason = detectionReason;
    }

    public static LogResponseDTO fromLogEvent(LogEvent event) {
        return new LogResponseDTO(
                event.getEventTime(),
                event.getSeverity(),
                event.getEventName(),
                event.getUserIdentity() != null ? event.getUserIdentity().getUserName() : "Unknown",
                event.getResource() != null ? event.getResource().getResourceName() : "Unknown",
                event.getSourceIPAddress(),
                event.getEventOutcome(),
                event.getDetectionReason()
        );
    }

    public String getTimestamp() { return timestamp; }
    public String getSeverity() { return severity; }
    public String getEventType() { return eventType; }
    public String getUser() { return user; }
    public String getResource() { return resource; }
    public String getIp() { return ip; }
    public String getStatus() { return status; }
    public String getDetectionReason() { return detectionReason; }
}
