package com.cloudforensics.model;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

public class LogEvent {

    private String eventTime;
    private String eventName;
    private UserIdentity userIdentity;
    private String sourceIPAddress;
    private CloudResource resource;
    private String eventOutcome;
    private String cloudProvider;
    private String region;

    // Detection Engine fields
    private String severity;
    private String detectionReason;

    public LogEvent() {}

    public LogEvent(String eventTime, String eventName, UserIdentity userIdentity,
                    String sourceIPAddress, CloudResource resource, String eventOutcome,
                    String cloudProvider, String region) {
        this.eventTime = eventTime;
        this.eventName = eventName;
        this.userIdentity = userIdentity;
        this.sourceIPAddress = sourceIPAddress;
        this.resource = resource;
        this.eventOutcome = eventOutcome;
        this.cloudProvider = cloudProvider;
        this.region = region;
    }

    // =========================
    // RAW GETTERS / SETTERS
    // =========================

    public String getEventTime() { return eventTime; }
    public void setEventTime(String eventTime) { this.eventTime = eventTime; }

    public String getEventName() { return eventName; }
    public void setEventName(String eventName) { this.eventName = eventName; }

    public UserIdentity getUserIdentity() { return userIdentity; }
    public void setUserIdentity(UserIdentity userIdentity) { this.userIdentity = userIdentity; }

    public String getSourceIPAddress() { return sourceIPAddress; }
    public void setSourceIPAddress(String sourceIPAddress) { this.sourceIPAddress = sourceIPAddress; }

    public CloudResource getResource() { return resource; }
    public void setResource(CloudResource resource) { this.resource = resource; }

    public String getEventOutcome() { return eventOutcome; }
    public void setEventOutcome(String eventOutcome) { this.eventOutcome = eventOutcome; }

    public String getCloudProvider() { return cloudProvider; }
    public void setCloudProvider(String cloudProvider) { this.cloudProvider = cloudProvider; }

    public String getRegion() { return region; }
    public void setRegion(String region) { this.region = region; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getDetectionReason() { return detectionReason; }
    public void setDetectionReason(String detectionReason) { this.detectionReason = detectionReason; }

    // =========================
    // TIMELINE HELPERS (CRITICAL)
    // =========================

    /**
     * Robust timestamp parsing (AWS/Azure compatible)
     */
    public LocalDateTime getTimestamp() {
        if (eventTime == null || eventTime.isEmpty()) {
            return LocalDateTime.MIN;
        }

        try {
            // Handles: 2024-03-30T10:15:30Z
            return OffsetDateTime.parse(eventTime).toLocalDateTime();
        } catch (DateTimeParseException e1) {
            try {
                // Handles: 2024-03-30T10:15:30
                return LocalDateTime.parse(eventTime, DateTimeFormatter.ISO_DATE_TIME);
            } catch (DateTimeParseException e2) {
                return LocalDateTime.MIN;
            }
        }
    }

    /**
     * Safe user extraction
     */
    public String getUserId() {
        if (userIdentity != null && userIdentity.getUserName() != null) {
            return userIdentity.getUserName().trim();
        }
        return "UNKNOWN_USER";
    }

    /**
     * Safe IP extraction
     */
    public String getIpAddress() {
        if (sourceIPAddress != null && !sourceIPAddress.isEmpty()) {
            return sourceIPAddress.trim();
        }
        return "UNKNOWN_IP";
    }

    /**
     * Normalize action name
     */
    public String getAction() {
        if (eventName != null && !eventName.isEmpty()) {
            return eventName.trim().toUpperCase();
        }
        return "UNKNOWN_ACTION";
    }

    /**
     * Safe resource extraction
     */
    public String getResourceName() {
        if (resource != null && resource.getResourceName() != null) {
            return resource.getResourceName().trim();
        }
        return "UNKNOWN_RESOURCE";
    }
}