package com.cloudforensics.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Document(collection = "cases")
public class IncidentCase {
    @Id
    private String caseId;
    private String user;
    private String ip;
    private String severity;
    private int linkedEventCount;
    private List<LogResponseDTO> relatedEvents;
    private String correlationReason;

    public IncidentCase() {
    }

    public IncidentCase(String caseId, String user, String ip, String severity,
                        int linkedEventCount, List<LogResponseDTO> relatedEvents, String correlationReason) {
        this.caseId = caseId;
        this.user = user;
        this.ip = ip;
        this.severity = severity;
        this.linkedEventCount = linkedEventCount;
        this.relatedEvents = relatedEvents;
        this.correlationReason = correlationReason;
    }

    public String getCaseId() {
        return caseId;
    }

    public String getUser() {
        return user;
    }

    public String getIp() {
        return ip;
    }

    public String getSeverity() {
        return severity;
    }

    public int getLinkedEventCount() {
        return linkedEventCount;
    }

    public List<LogResponseDTO> getRelatedEvents() {
        return relatedEvents;
    }

    public String getCorrelationReason() {
        return correlationReason;
    }
}