package com.cloudforensics.service;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.IncidentCase;
import com.cloudforensics.model.LogEvent;
import com.cloudforensics.model.StoredEvidence;
import com.cloudforensics.repository.StoredEvidenceRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class EvidenceLockerService {

    private final StoredEvidenceRepository repository;
    private final ObjectMapper objectMapper;

    public EvidenceLockerService(StoredEvidenceRepository repository) {
        this.repository = repository;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules(); // Re-register JavaTimeModules if any
    }

    /**
     * Stores forensic outputs as locked evidence.
     */
    public StoredEvidence storeEvidence(Object dataObj, String dataType) {
        try {
            String dataJson = objectMapper.writeValueAsString(dataObj);
            String sha256Hash = generateSha256(dataJson);
            
            String evidenceId = "EV-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
            
            StoredEvidence evidence = new StoredEvidence(evidenceId, dataType, dataJson, sha256Hash, Instant.now());
            return repository.save(evidence);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize evidence data", e);
        }
    }

    /**
     * Batch stores parsed logs, generated alerts, and correlated incident cases.
     */
    public void storeBatch(List<LogEvent> logs, List<Alert> alerts, List<IncidentCase> cases) {
        logs.forEach(log -> storeEvidence(log, "LOG"));
        alerts.forEach(alert -> storeEvidence(alert, "ALERT"));
        cases.forEach(incidentCase -> storeEvidence(incidentCase, "CASE"));
    }

    /**
     * Lists all stored evidence.
     */
    public List<StoredEvidence> getAllEvidence() {
        return repository.findAll();
    }

    /**
     * Verifies the integrity of a specific evidence record.
     */
    public IntegrityResult verifyIntegrity(String evidenceId) {
        StoredEvidence evidence = repository.findByEvidenceId(evidenceId)
                .orElseThrow(() -> new RuntimeException("Evidence not found: " + evidenceId));
                
        String recalculatedHash = generateSha256(evidence.getData());
        boolean isValid = recalculatedHash.equals(evidence.getSha256Hash());
        
        return new IntegrityResult(evidenceId, isValid, evidence.getSha256Hash(), recalculatedHash);
    }
    
    /**
     * Helper to verify all records and return a summary of tampered files.
     */
    public List<IntegrityResult> verifyAll() {
        List<StoredEvidence> allRecords = repository.findAll();
        List<IntegrityResult> results = new ArrayList<>();
        
        for (StoredEvidence record : allRecords) {
            String recalculatedHash = generateSha256(record.getData());
            boolean isValid = recalculatedHash.equals(record.getSha256Hash());
            results.add(new IntegrityResult(record.getEvidenceId(), isValid, record.getSha256Hash(), recalculatedHash));
        }
        return results;
    }

    /**
     * Generates a SHA-256 hash for a given string.
     */
    private String generateSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(encodedhash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize SHA-256 algorithm", e);
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Inner class for returning verification results
    public static class IntegrityResult {
        private String evidenceId;
        private boolean valid;
        private String storedHash;
        private String calculatedHash;

        public IntegrityResult(String evidenceId, boolean valid, String storedHash, String calculatedHash) {
            this.evidenceId = evidenceId;
            this.valid = valid;
            this.storedHash = storedHash;
            this.calculatedHash = calculatedHash;
        }

        public String getEvidenceId() { return evidenceId; }
        public boolean isValid() { return valid; }
        public String getStoredHash() { return storedHash; }
        public String getCalculatedHash() { return calculatedHash; }
    }
}
