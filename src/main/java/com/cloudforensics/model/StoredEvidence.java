package com.cloudforensics.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "stored_evidence")
public class StoredEvidence {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String evidenceId;

    @Column(nullable = false)
    private String dataType; // E.g., LOG, ALERT, CASE

    @Lob
    @Column(columnDefinition = "TEXT", nullable = false)
    private String data; // The JSON string

    @Column(nullable = false)
    private String sha256Hash;

    @Column(nullable = false)
    private Instant timestamp;

    public StoredEvidence() {}

    public StoredEvidence(String evidenceId, String dataType, String data, String sha256Hash, Instant timestamp) {
        this.evidenceId = evidenceId;
        this.dataType = dataType;
        this.data = data;
        this.sha256Hash = sha256Hash;
        this.timestamp = timestamp;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEvidenceId() {
        return evidenceId;
    }

    public void setEvidenceId(String evidenceId) {
        this.evidenceId = evidenceId;
    }

    public String getDataType() {
        return dataType;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public void setSha256Hash(String sha256Hash) {
        this.sha256Hash = sha256Hash;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
}
