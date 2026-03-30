package com.cloudforensics.service;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.IncidentCase;
import com.cloudforensics.model.LogEvent;
import com.cloudforensics.model.LogResponseDTO;
import com.cloudforensics.model.TimelineEvent;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Core forensic engine that correlates individual log events and alerts
 * into coherent attack timelines and incident cases.
 */
@Service
public class CorrelationService {

    @Autowired(required = false)
    private DetectionRuleService detectionRuleService;

    // =========================================================================
    //  TIMELINE GENERATION
    // =========================================================================

    /**
     * Generates a full forensic attack timeline from a list of log events.
     * Each event is enriched with:
     *   - A human-readable narrative description
     *   - Severity classification from the detection engine
     *   - MITRE ATT&CK attack phase mapping
     *   - Activity gap detection (marks gaps > 30 minutes)
     */
    public List<TimelineEvent> generateTimeline(List<LogEvent> events) {

        if (events == null || events.isEmpty()) {
            return new ArrayList<>();
        }

        // Step 1: Sort events chronologically
        events.sort(Comparator.comparing(LogEvent::getTimestamp));

        List<TimelineEvent> timeline = new ArrayList<>();
        LogEvent previous = null;

        // Track cumulative state for contextual descriptions
        Map<String, Integer> failedLoginCounts = new HashMap<>();

        for (LogEvent e : events) {

            // Step 2: Check for activity gap before this event
            if (previous != null) {
                long gapMinutes = Duration.between(previous.getTimestamp(), e.getTimestamp()).toMinutes();
                if (gapMinutes > 30) {
                    timeline.add(createGapMarker(e.getTimestamp(), gapMinutes));
                }
            }

            // Step 3: Build the timeline event
            TimelineEvent t = new TimelineEvent();

            t.setTimestamp(e.getTimestamp());
            t.setUser(e.getUserId());
            t.setIp(e.getIpAddress());
            t.setAction(e.getEventName());       // original case (e.g. "ConsoleLogin")
            t.setResource(e.getResourceName());
            t.setStatus(e.getEventOutcome());
            t.setGapMarker(false);

            // Step 4: Track failed logins for contextual narration
            if ("ConsoleLogin".equalsIgnoreCase(e.getEventName())
                    && "FAILURE".equalsIgnoreCase(e.getEventOutcome())) {
                int count = failedLoginCounts.getOrDefault(e.getUserId(), 0) + 1;
                failedLoginCounts.put(e.getUserId(), count);
            }

            // Step 5: Generate forensic narrative
            t.setDescription(generateDescription(e, failedLoginCounts));

            // Step 6: Map to MITRE ATT&CK attack phase
            t.setAttackStage(mapAttackStage(e));

            // Step 7: Determine severity via detection engine
            String severity = "INFO";
            boolean flagged = false;

            if (detectionRuleService != null) {
                try {
                    severity = detectionRuleService.getSeverity(e);
                    flagged = detectionRuleService.isSuspicious(e);
                } catch (Exception ex) {
                    severity = fallbackSeverity(e);
                    flagged = fallbackFlag(e);
                }
            } else {
                severity = fallbackSeverity(e);
                flagged = fallbackFlag(e);
            }

            t.setSeverity(severity);
            t.setFlagged(flagged);

            timeline.add(t);
            previous = e;
        }

        return timeline;
    }

    // =========================================================================
    //  DESCRIPTION GENERATOR — Forensic Narrative for each event
    // =========================================================================

    /**
     * Creates a human-readable forensic description for each log event.
     * Uses the actual event names from cloud logs (ConsoleLogin, AttachUserPolicy, etc.)
     */
    private String generateDescription(LogEvent e, Map<String, Integer> failedLoginCounts) {

        String eventName = e.getEventName();
        if (eventName == null) return "Unknown activity recorded";

        String user = e.getUserId();
        String ip = e.getIpAddress();
        String resource = e.getResourceName();
        String outcome = e.getEventOutcome();

        switch (eventName) {

            // ---- Authentication Events ----
            case "ConsoleLogin":
                if ("FAILURE".equalsIgnoreCase(outcome)) {
                    int count = failedLoginCounts.getOrDefault(user, 1);
                    if (count >= 3) {
                        return "⚠ Brute-force pattern: " + count + " consecutive failed login attempts by '"
                                + user + "' from IP " + ip + " — possible credential stuffing attack";
                    }
                    return "Failed console login attempt by '" + user + "' from IP " + ip;
                }
                // Check if this success came after failures
                if (failedLoginCounts.getOrDefault(user, 0) >= 2) {
                    return "⚠ Successful login by '" + user + "' from IP " + ip
                            + " AFTER " + failedLoginCounts.get(user)
                            + " failed attempts — possible credential compromise";
                }
                return "User '" + user + "' successfully authenticated to console from IP " + ip;

            // ---- Privilege Escalation Events ----
            case "AttachUserPolicy":
                return "⚠ IAM policy attached to user by '" + user
                        + "' — potential privilege escalation to gain elevated permissions";

            case "PutUserPolicy":
                return "⚠ Inline IAM policy modified by '" + user
                        + "' — direct policy injection detected";

            case "CreateAccessKey":
                return "⚠ New API access key created by '" + user
                        + "' — attacker may be establishing persistent access";

            // ---- Discovery / Reconnaissance Events ----
            case "ListBuckets":
                return "User '" + user + "' enumerated all S3 storage buckets from IP " + ip
                        + " — cloud storage reconnaissance activity";

            case "DescribeInstances":
                return "User '" + user + "' queried EC2 instance details from IP " + ip
                        + " — infrastructure reconnaissance activity";

            case "ListUsers":
                return "User '" + user + "' listed all IAM users from IP " + ip
                        + " — identity reconnaissance / account enumeration";

            // ---- Data Access / Exfiltration Events ----
            case "GetObject":
                return "⚠ User '" + user + "' downloaded object from " + resource
                        + " — potential data exfiltration";

            case "PutObject":
                return "User '" + user + "' uploaded object to " + resource;

            case "DeleteObject":
                return "⚠ User '" + user + "' deleted object from " + resource
                        + " — potential evidence destruction";

            // ---- Resource Modification Events ----
            case "DeleteBucket":
                return "⚠ CRITICAL: User '" + user + "' deleted an S3 bucket — "
                        + "possible destructive action or evidence tampering";

            case "StopInstances":
                return "⚠ User '" + user + "' stopped EC2 instances — "
                        + "possible service disruption or anti-forensics";

            case "CreateUser":
                return "⚠ New IAM user created by '" + user
                        + "' — potential persistence mechanism via backdoor account";

            // ---- Default ----
            default:
                return "Event '" + eventName + "' performed by '" + user
                        + "' on resource '" + resource + "' from IP " + ip;
        }
    }

    // =========================================================================
    //  MITRE ATT&CK PHASE MAPPING
    // =========================================================================

    /**
     * Maps each event to its corresponding MITRE ATT&CK attack phase.
     * This helps reconstruct the kill chain during incident investigation.
     */
    private String mapAttackStage(LogEvent e) {

        String eventName = e.getEventName();
        if (eventName == null) return "Unknown";

        String outcome = e.getEventOutcome();

        switch (eventName) {
            case "ConsoleLogin":
                if ("FAILURE".equalsIgnoreCase(outcome)) {
                    return "Initial Access — Brute Force (T1110)";
                }
                return "Initial Access — Valid Accounts (T1078)";

            case "AttachUserPolicy":
            case "PutUserPolicy":
            case "CreateAccessKey":
                return "Privilege Escalation (T1078.004)";

            case "CreateUser":
                return "Persistence — Create Account (T1136)";

            case "ListBuckets":
            case "DescribeInstances":
            case "ListUsers":
                return "Discovery (T1580 / T1087)";

            case "GetObject":
                return "Collection — Data from Cloud Storage (T1530)";

            case "DeleteObject":
            case "DeleteBucket":
                return "Impact — Data Destruction (T1485)";

            case "StopInstances":
                return "Impact — Service Stop (T1489)";

            default:
                return "Execution";
        }
    }

    // =========================================================================
    //  EVENT CORRELATION — Groups alerts into Incident Cases
    // =========================================================================

    /**
     * Correlates log events and alerts into Incident Cases.
     * Groups events by user+IP combination to identify multi-stage attacks.
     * Each case contains the full chain of related events for investigation.
     */
    public List<IncidentCase> correlateCases(List<LogEvent> logs, List<Alert> alerts) {

        if (logs == null || logs.isEmpty()) {
            return new ArrayList<>();
        }

        // Step 1: Group log events by (user, IP) pairs
        Map<String, List<LogEvent>> eventsByActor = new LinkedHashMap<>();

        for (LogEvent log : logs) {
            String user = log.getUserId();
            String ip = log.getIpAddress();
            String actorKey = user + "|" + ip;
            eventsByActor.computeIfAbsent(actorKey, k -> new ArrayList<>()).add(log);
        }

        List<IncidentCase> cases = new ArrayList<>();
        int caseCounter = 1;

        // Step 2: Build a case for each actor group that has suspicious activity
        for (Map.Entry<String, List<LogEvent>> entry : eventsByActor.entrySet()) {

            List<LogEvent> actorLogs = entry.getValue();
            String[] parts = entry.getKey().split("\\|", 2);
            String user = parts[0];
            String ip = parts.length > 1 ? parts[1] : "UNKNOWN_IP";

            // Only create a case if there's potentially interesting activity (2+ events)
            if (actorLogs.size() < 2) continue;

            // Sort this actor's events chronologically
            actorLogs.sort(Comparator.comparing(LogEvent::getTimestamp));

            // Step 3: Determine the highest severity across this actor's events
            String caseSeverity = determineHighestSeverity(actorLogs);

            // Step 4: Build the correlation reason (attack narrative)
            String correlationReason = buildCorrelationReason(actorLogs, alerts, user);

            // Step 5: Convert to DTOs for the response
            List<LogResponseDTO> relatedEvents = actorLogs.stream()
                    .map(LogResponseDTO::fromLogEvent)
                    .collect(Collectors.toList());

            // Step 6: Build the case
            String caseId = String.format("CASE-%03d", caseCounter++);
            IncidentCase incidentCase = new IncidentCase(
                    caseId,
                    user,
                    ip,
                    caseSeverity,
                    actorLogs.size(),
                    relatedEvents,
                    correlationReason
            );

            cases.add(incidentCase);
        }

        // Sort cases: highest severity first
        cases.sort((a, b) -> severityRank(b.getSeverity()) - severityRank(a.getSeverity()));

        return cases;
    }

    /**
     * Determines the highest severity level across a group of log events.
     */
    private String determineHighestSeverity(List<LogEvent> logs) {
        int maxRank = 0;
        for (LogEvent log : logs) {
            String sev = (detectionRuleService != null)
                    ? detectionRuleService.getSeverity(log) : fallbackSeverity(log);
            maxRank = Math.max(maxRank, severityRank(sev));
        }
        switch (maxRank) {
            case 4: return "CRITICAL";
            case 3: return "HIGH";
            case 2: return "MEDIUM";
            case 1: return "LOW";
            default: return "INFO";
        }
    }

    /**
     * Ranks severity for comparison: higher rank = more severe.
     */
    private int severityRank(String severity) {
        if (severity == null) return 0;
        switch (severity.toUpperCase()) {
            case "CRITICAL": return 4;
            case "HIGH":     return 3;
            case "MEDIUM":   return 2;
            case "LOW":      return 1;
            default:         return 0;
        }
    }

    /**
     * Builds a human-readable correlation reason that explains WHY
     * these events were grouped into a case — the attack narrative.
     */
    private String buildCorrelationReason(List<LogEvent> logs, List<Alert> alerts, String user) {
        List<String> stages = new ArrayList<>();

        boolean hasFailedLogin = false;
        boolean hasSuccessLogin = false;
        boolean hasPrivEsc = false;
        boolean hasRecon = false;
        boolean hasDataAccess = false;

        for (LogEvent log : logs) {
            String event = log.getEventName();
            if (event == null) continue;

            if ("ConsoleLogin".equals(event) && "FAILURE".equalsIgnoreCase(log.getEventOutcome())) {
                hasFailedLogin = true;
            }
            if ("ConsoleLogin".equals(event) && "SUCCESS".equalsIgnoreCase(log.getEventOutcome())) {
                hasSuccessLogin = true;
            }
            if ("AttachUserPolicy".equals(event) || "PutUserPolicy".equals(event)
                    || "CreateAccessKey".equals(event)) {
                hasPrivEsc = true;
            }
            if ("ListBuckets".equals(event) || "DescribeInstances".equals(event)
                    || "ListUsers".equals(event)) {
                hasRecon = true;
            }
            if ("GetObject".equals(event) || "DeleteObject".equals(event)) {
                hasDataAccess = true;
            }
        }

        // Build the narrative
        if (hasFailedLogin) stages.add("Brute-force login attempts");
        if (hasSuccessLogin && hasFailedLogin) stages.add("Credential compromise (login after failures)");
        else if (hasSuccessLogin) stages.add("Authenticated access");
        if (hasPrivEsc) stages.add("Privilege escalation via IAM modification");
        if (hasRecon) stages.add("Cloud infrastructure reconnaissance");
        if (hasDataAccess) stages.add("Sensitive data access / exfiltration");

        if (stages.isEmpty()) {
            return "Multi-event activity detected for user '" + user + "'";
        }

        return "Attack chain: " + String.join(" → ", stages);
    }

    // =========================================================================
    //  GAP MARKER
    // =========================================================================

    /**
     * Creates a visual gap marker in the timeline when there's a significant
     * pause (>30 minutes) between events. Helps forensic readability.
     */
    private TimelineEvent createGapMarker(LocalDateTime time, long gapMinutes) {
        TimelineEvent gap = new TimelineEvent();
        gap.setTimestamp(time);
        gap.setGapMarker(true);
        gap.setSeverity("INFO");
        gap.setFlagged(false);

        if (gapMinutes >= 1440) {
            long days = gapMinutes / 1440;
            gap.setDescription("──── " + days + " day(s) of inactivity ────");
        } else if (gapMinutes >= 60) {
            long hours = gapMinutes / 60;
            gap.setDescription("──── " + hours + " hour(s) of inactivity ────");
        } else {
            gap.setDescription("──── " + gapMinutes + " minute(s) of inactivity ────");
        }

        return gap;
    }

    // =========================================================================
    //  FALLBACKS (if DetectionRuleService not ready)
    // =========================================================================

    private String fallbackSeverity(LogEvent e) {
        String event = e.getEventName();
        if (event == null) return "INFO";

        if ("GetObject".equals(event) || "DeleteObject".equals(event)
                || "DeleteBucket".equals(event)) return "CRITICAL";
        if ("AttachUserPolicy".equals(event) || "PutUserPolicy".equals(event)
                || "CreateAccessKey".equals(event)) return "HIGH";
        if ("ConsoleLogin".equals(event) && "FAILURE".equalsIgnoreCase(e.getEventOutcome())) return "MEDIUM";

        return "INFO";
    }

    private boolean fallbackFlag(LogEvent e) {
        String sev = fallbackSeverity(e);
        return "MEDIUM".equals(sev) || "HIGH".equals(sev) || "CRITICAL".equals(sev);
    }
}