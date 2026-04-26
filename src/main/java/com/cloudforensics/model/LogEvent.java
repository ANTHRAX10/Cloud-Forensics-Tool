package com.cloudforensics.model;

public class LogEvent {
    private String eventTime;
    private String eventName;
    private UserIdentity userIdentity;
    private String sourceIPAddress;
    private CloudResource resource;
    private String eventOutcome;
    private String cloudProvider;
    private String region;
    private String userAgent;

    // Enrichment fields (Populated by Detection Engine)
    private String severity;
    private String detectionReason;

    public LogEvent() {
    }

    public LogEvent(String eventTime, String eventName, UserIdentity userIdentity,
                    String sourceIPAddress, CloudResource resource, String eventOutcome,
                    String cloudProvider, String region, String userAgent) {
        this.eventTime = eventTime;
        this.eventName = eventName;
        this.userIdentity = userIdentity;
        this.sourceIPAddress = sourceIPAddress;
        this.resource = resource;
        this.eventOutcome = eventOutcome;
        this.cloudProvider = cloudProvider;
        this.region = region;
        this.userAgent = userAgent;
    }

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

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getDetectionReason() { return detectionReason; }
    public void setDetectionReason(String detectionReason) { this.detectionReason = detectionReason; }
}