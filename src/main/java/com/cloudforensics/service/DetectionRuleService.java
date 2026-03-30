package com.cloudforensics.service;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.LogEvent;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class DetectionRuleService {

    // ── Thresholds ──────────────────────────────────────────────────────────────
    private static final int FAILED_LOGIN_BURST_THRESHOLD = 3;
    private static final int BRUTE_FORCE_USER_THRESHOLD = 3;
    private static final int S3_EXFIL_THRESHOLD = 10;
    private static final int API_BURST_THRESHOLD = 20;
    private static final int IMPOSSIBLE_TRAVEL_MINUTES = 5;
    private static final int ACCESS_KEY_ABUSE_MINUTES = 30;
    private static final int PRIV_CHAIN_MINUTES = 60;
    private static final int S3_EXFIL_WINDOW_MINUTES = 10;
    private static final int API_BURST_WINDOW_MINUTES = 5;
    private static final int UNUSUAL_LOGIN_HOUR_START = 0;  // midnight
    private static final int UNUSUAL_LOGIN_HOUR_END = 5;    // 5 AM

    // ── IAM recon event names ───────────────────────────────────────────────────
    private static final Set<String> IAM_RECON_EVENTS = Set.of(
            "ListUsers", "ListRoles", "ListGroups", "ListPolicies",
            "GetUser", "GetRole", "GetPolicy", "ListAccessKeys",
            "ListAttachedUserPolicies", "ListAttachedRolePolicies",
            "ListGroupsForUser", "ListMFADevices"
    );

    // ── Sensitive actions ───────────────────────────────────────────────────────
    private static final Set<String> SENSITIVE_ACTIONS = Set.of(
            "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
            "DeleteTrail", "StopLogging", "CreateUser", "DeleteUser",
            "AttachRolePolicy", "PutRolePolicy", "CreateRole",
            "DeactivateMFADevice", "DeleteAccessKey"
    );

    // ── Security control events ─────────────────────────────────────────────────
    private static final Set<String> SECURITY_CONTROL_EVENTS = Set.of(
            "StopLogging", "DeleteTrail", "UpdateTrail",
            "DeleteFlowLogs", "DisableAlarmActions",
            "DeleteDetector", "DisableKey", "ArchiveFindings"
    );

    // ── Privilege escalation chain events ────────────────────────────────────────
    private static final Set<String> PRIV_ESCALATION_EVENTS = Set.of(
            "AttachUserPolicy", "PutUserPolicy", "CreateAccessKey"
    );

    // ── Time parser formats ─────────────────────────────────────────────────────
    private static final DateTimeFormatter[] TIME_FORMATTERS = {
            DateTimeFormatter.ISO_DATE_TIME,
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX")
    };

    // ══════════════════════════════════════════════════════════════════════════════
    //  DETECTION CONTEXT — built once, shared across all detection methods
    // ══════════════════════════════════════════════════════════════════════════════
    private static class DetectionContext {
        final List<LogEvent> allLogs;
        final Map<String, List<LogEvent>> userEventMap;
        final Map<String, List<LogEvent>> ipEventMap;
        final Map<String, Set<String>> userIPs;
        final Map<String, LocalDateTime> parsedTimes;

        DetectionContext(List<LogEvent> logs) {
            this.allLogs = logs;
            this.userEventMap = new HashMap<>();
            this.ipEventMap = new HashMap<>();
            this.userIPs = new HashMap<>();
            this.parsedTimes = new HashMap<>();

            for (LogEvent log : logs) {
                String userName = extractUserName(log);
                String ip = log.getSourceIPAddress();
                String eventTimeStr = log.getEventTime();

                // Build user → events map
                userEventMap.computeIfAbsent(userName, k -> new ArrayList<>()).add(log);

                // Build IP → events map
                if (ip != null && !ip.isEmpty()) {
                    ipEventMap.computeIfAbsent(ip, k -> new ArrayList<>()).add(log);
                }

                // Build user → IPs set
                if (ip != null && !ip.isEmpty()) {
                    userIPs.computeIfAbsent(userName, k -> new HashSet<>()).add(ip);
                }

                // Pre-parse event times (keyed by object identity)
                if (eventTimeStr != null) {
                    LocalDateTime parsed = parseTime(eventTimeStr);
                    if (parsed != null) {
                        parsedTimes.put(System.identityHashCode(log) + "", parsed);
                    }
                }
            }
        }

        LocalDateTime getTime(LogEvent log) {
            return parsedTimes.get(System.identityHashCode(log) + "");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //  ENRICH LOGS — severity + detection reason assignment
    // ══════════════════════════════════════════════════════════════════════════════
    public void enrichLogs(List<LogEvent> logs) {
        Map<String, Integer> userFailureMap = new HashMap<>();

        for (LogEvent log : logs) {
            String eventName = log.getEventName();
            String outcome = log.getEventOutcome();
            String userName = extractUserName(log);

            // Defaults
            log.setSeverity("INFO");
            log.setDetectionReason("Normal operation");

            if (eventName == null) continue;

            // Root account usage → CRITICAL
            if (isRootAccount(log)) {
                log.setSeverity("CRITICAL");
                log.setDetectionReason("Root account activity detected");
                continue;
            }

            // Security control disable → CRITICAL
            if (SECURITY_CONTROL_EVENTS.contains(eventName)) {
                log.setSeverity("CRITICAL");
                log.setDetectionReason("Security control modification: " + eventName);
                continue;
            }

            // Failed login handling
            if ("ConsoleLogin".equals(eventName) && "FAILURE".equalsIgnoreCase(outcome)) {
                int count = userFailureMap.getOrDefault(userName, 0) + 1;
                userFailureMap.put(userName, count);

                if (count >= FAILED_LOGIN_BURST_THRESHOLD) {
                    log.setSeverity("MEDIUM");
                    log.setDetectionReason("Multiple failed login attempts detected (" + count + ")");
                } else {
                    log.setSeverity("LOW");
                    log.setDetectionReason("Failed login attempt");
                }
                continue;
            }

            // Privilege escalation activity → HIGH
            if (PRIV_ESCALATION_EVENTS.contains(eventName)) {
                log.setSeverity("HIGH");
                log.setDetectionReason("Potential privilege escalation activity detected");
                continue;
            }

            // IAM reconnaissance → MEDIUM
            if (IAM_RECON_EVENTS.contains(eventName)) {
                log.setSeverity("MEDIUM");
                log.setDetectionReason("IAM reconnaissance activity: " + eventName);
                continue;
            }

            // Data exfiltration suspicion → HIGH
            if ("GetObject".equals(eventName)) {
                log.setSeverity("HIGH");
                log.setDetectionReason("Potential data exfiltration via object access");
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //  DETECT ALERTS — main entry point
    // ══════════════════════════════════════════════════════════════════════════════
    public List<Alert> detectAlerts(List<LogEvent> logs) {
        List<Alert> alerts = new ArrayList<>();

        // Build context once — all detection methods reuse it
        DetectionContext ctx = new DetectionContext(logs);

        // ── CRITICAL detections ─────────────────────────────────────────────────
        addImpossibleTravelAlert(ctx, alerts);
        addAccessKeyAbuseAlert(ctx, alerts);
        addPrivilegeEscalationChainAlert(ctx, alerts);
        addTimedS3ExfiltrationAlert(ctx, alerts);
        addRootAccountUsageAlert(ctx, alerts);
        addSecurityControlDisableAlert(ctx, alerts);

        // ── HIGH detections ─────────────────────────────────────────────────────
        addFailedLoginBurstAlert(ctx, alerts);
        addBruteForceAttackAlert(ctx, alerts);
        addMultipleIPLoginAlert(ctx, alerts);
        addAPIBurstAlert(ctx, alerts);
        addIAMReconnaissanceAlert(ctx, alerts);
        addUnusualLoginTimeAlert(ctx, alerts);

        // ── MEDIUM detections ───────────────────────────────────────────────────
        addFirstTimeSensitiveActionAlert(ctx, alerts);
        addNewIPDetectionAlert(ctx, alerts);

        return alerts;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //  CRITICAL DETECTIONS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * Impossible Travel: same user logs events from multiple IPs within a short window.
     */
    private void addImpossibleTravelAlert(DetectionContext ctx, List<Alert> alerts) {
        for (Map.Entry<String, List<LogEvent>> entry : ctx.userEventMap.entrySet()) {
            String user = entry.getKey();
            if ("Unknown".equals(user)) continue;

            List<LogEvent> events = entry.getValue();
            // Need at least 2 events with different IPs
            Set<String> ips = ctx.userIPs.getOrDefault(user, Collections.emptySet());
            if (ips.size() < 2) continue;

            // Sort by time and check for IP switches within the window
            List<LogEvent> timed = filterWithTime(ctx, events);
            if (timed.size() < 2) continue;

            timed.sort(Comparator.comparing(ctx::getTime));

            for (int i = 1; i < timed.size(); i++) {
                LogEvent prev = timed.get(i - 1);
                LogEvent curr = timed.get(i);
                String prevIP = prev.getSourceIPAddress();
                String currIP = curr.getSourceIPAddress();

                if (prevIP == null || currIP == null || prevIP.equals(currIP)) continue;

                LocalDateTime t1 = ctx.getTime(prev);
                LocalDateTime t2 = ctx.getTime(curr);

                if (t1 != null && t2 != null
                        && ChronoUnit.MINUTES.between(t1, t2) <= IMPOSSIBLE_TRAVEL_MINUTES) {
                    alerts.add(createAlert(
                            curr.getEventTime(), "Impossible Travel", "CRITICAL",
                            user, currIP, curr.getEventName(),
                            "User '" + user + "' accessed from IP " + prevIP
                                    + " and " + currIP + " within "
                                    + ChronoUnit.MINUTES.between(t1, t2) + " minutes — possible credential compromise."
                    ));
                    break; // One alert per user
                }
            }
        }
    }

    /**
     * Access Key Abuse: CreateAccessKey followed by usage from a new IP within the window.
     */
    private void addAccessKeyAbuseAlert(DetectionContext ctx, List<Alert> alerts) {
        for (Map.Entry<String, List<LogEvent>> entry : ctx.userEventMap.entrySet()) {
            String user = entry.getKey();
            if ("Unknown".equals(user)) continue;

            List<LogEvent> events = entry.getValue();
            LogEvent createKeyEvent = null;

            for (LogEvent log : events) {
                if ("CreateAccessKey".equals(log.getEventName())) {
                    createKeyEvent = log;
                    break;
                }
            }
            if (createKeyEvent == null) continue;

            LocalDateTime createTime = ctx.getTime(createKeyEvent);
            String createIP = createKeyEvent.getSourceIPAddress();
            if (createTime == null || createIP == null) continue;

            for (LogEvent log : events) {
                if (log == createKeyEvent) continue;
                LocalDateTime logTime = ctx.getTime(log);
                String logIP = log.getSourceIPAddress();

                if (logTime == null || logIP == null) continue;
                if (logIP.equals(createIP)) continue;
                if (!logTime.isAfter(createTime)) continue;

                if (ChronoUnit.MINUTES.between(createTime, logTime) <= ACCESS_KEY_ABUSE_MINUTES) {
                    alerts.add(createAlert(
                            log.getEventTime(), "Access Key Abuse", "CRITICAL",
                            user, logIP, log.getEventName(),
                            "Access key created by '" + user + "' from " + createIP
                                    + " was used from a different IP " + logIP
                                    + " within " + ACCESS_KEY_ABUSE_MINUTES + " minutes."
                    ));
                    break;
                }
            }
        }
    }

    /**
     * Privilege Escalation Chain: CreateUser → AttachUserPolicy → CreateAccessKey by same user.
     */
    private void addPrivilegeEscalationChainAlert(DetectionContext ctx, List<Alert> alerts) {
        for (Map.Entry<String, List<LogEvent>> entry : ctx.userEventMap.entrySet()) {
            String user = entry.getKey();
            if ("Unknown".equals(user)) continue;

            List<LogEvent> events = entry.getValue();
            LogEvent createUser = null;
            LogEvent attachPolicy = null;
            LogEvent createKey = null;

            // Find the chain in order
            List<LogEvent> timed = filterWithTime(ctx, events);
            timed.sort(Comparator.comparing(ctx::getTime));

            for (LogEvent log : timed) {
                String eventName = log.getEventName();
                if ("CreateUser".equals(eventName) && createUser == null) {
                    createUser = log;
                } else if ("AttachUserPolicy".equals(eventName) && createUser != null && attachPolicy == null) {
                    attachPolicy = log;
                } else if ("CreateAccessKey".equals(eventName) && attachPolicy != null && createKey == null) {
                    createKey = log;
                }
            }

            if (createUser != null && attachPolicy != null && createKey != null) {
                LocalDateTime t1 = ctx.getTime(createUser);
                LocalDateTime t3 = ctx.getTime(createKey);

                if (t1 != null && t3 != null
                        && ChronoUnit.MINUTES.between(t1, t3) <= PRIV_CHAIN_MINUTES) {
                    alerts.add(createAlert(
                            createKey.getEventTime(), "Privilege Escalation Chain", "CRITICAL",
                            user, createKey.getSourceIPAddress(), "CreateUser→AttachUserPolicy→CreateAccessKey",
                            "User '" + user + "' performed a full privilege escalation chain: "
                                    + "CreateUser → AttachUserPolicy → CreateAccessKey within "
                                    + PRIV_CHAIN_MINUTES + " minutes."
                    ));
                }
            }
        }
    }

    /**
     * Time-Based S3 Exfiltration: high GetObject count within a short window.
     */
    private void addTimedS3ExfiltrationAlert(DetectionContext ctx, List<Alert> alerts) {
        for (Map.Entry<String, List<LogEvent>> entry : ctx.userEventMap.entrySet()) {
            String user = entry.getKey();
            if ("Unknown".equals(user)) continue;

            List<LogEvent> getObjects = new ArrayList<>();
            for (LogEvent log : entry.getValue()) {
                if ("GetObject".equals(log.getEventName()) && ctx.getTime(log) != null) {
                    getObjects.add(log);
                }
            }

            if (getObjects.size() < S3_EXFIL_THRESHOLD) continue;

            getObjects.sort(Comparator.comparing(ctx::getTime));

            // Sliding window check
            int windowCount = countInWindow(ctx, getObjects, S3_EXFIL_WINDOW_MINUTES);
            if (windowCount >= S3_EXFIL_THRESHOLD) {
                LogEvent last = getObjects.get(getObjects.size() - 1);
                alerts.add(createAlert(
                        last.getEventTime(), "S3 Data Exfiltration", "CRITICAL",
                        user, last.getSourceIPAddress(), "GetObject",
                        "User '" + user + "' performed " + windowCount
                                + " S3 GetObject requests within " + S3_EXFIL_WINDOW_MINUTES
                                + " minutes — potential data exfiltration."
                ));
            }
        }
    }

    /**
     * Root Account Usage: any activity from the root account.
     */
    private void addRootAccountUsageAlert(DetectionContext ctx, List<Alert> alerts) {
        Set<String> alerted = new HashSet<>();
        for (LogEvent log : ctx.allLogs) {
            if (isRootAccount(log)) {
                String key = log.getEventName() + "|" + log.getSourceIPAddress();
                if (alerted.add(key)) {
                    alerts.add(createAlert(
                            log.getEventTime(), "Root Account Usage", "CRITICAL",
                            "root", log.getSourceIPAddress(), log.getEventName(),
                            "Root account activity detected: " + log.getEventName()
                                    + " from IP " + log.getSourceIPAddress()
                                    + ". Root account usage should be strictly limited."
                    ));
                }
            }
        }
    }

    /**
     * Security Control Disable: StopLogging, DeleteTrail, etc.
     */
    private void addSecurityControlDisableAlert(DetectionContext ctx, List<Alert> alerts) {
        for (LogEvent log : ctx.allLogs) {
            if (log.getEventName() != null && SECURITY_CONTROL_EVENTS.contains(log.getEventName())) {
                String user = extractUserName(log);
                alerts.add(createAlert(
                        log.getEventTime(), "Security Control Disabled", "CRITICAL",
                        user, log.getSourceIPAddress(), log.getEventName(),
                        "User '" + user + "' executed security control modification: "
                                + log.getEventName() + " from IP " + log.getSourceIPAddress()
                                + ". This may indicate an attempt to cover tracks."
                ));
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //  HIGH DETECTIONS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * Failed Login Burst: multiple failed logins for same user.
     */
    private void addFailedLoginBurstAlert(DetectionContext ctx, List<Alert> alerts) {
        for (Map.Entry<String, List<LogEvent>> entry : ctx.userEventMap.entrySet()) {
            String user = entry.getKey();
            if ("Unknown".equals(user)) continue;

            List<LogEvent> failures = new ArrayList<>();
            for (LogEvent log : entry.getValue()) {
                if ("ConsoleLogin".equals(log.getEventName())
                        && "FAILURE".equalsIgnoreCase(log.getEventOutcome())) {
                    failures.add(log);
                }
            }

            if (failures.size() >= FAILED_LOGIN_BURST_THRESHOLD) {
                LogEvent last = failures.get(failures.size() - 1);
                alerts.add(createAlert(
                        last.getEventTime(), "Failed Login Burst", "HIGH",
                        user, last.getSourceIPAddress(), "ConsoleLogin",
                        "Multiple failed login attempts (" + failures.size()
                                + ") detected for user '" + user
                                + "' from IP " + last.getSourceIPAddress() + "."
                ));
            }
        }
    }

    /**
     * Brute Force Attack: same IP targeting multiple user accounts.
     */
    private void addBruteForceAttackAlert(DetectionContext ctx, List<Alert> alerts) {
        // Build IP → set of failed-login users
        Map<String, Set<String>> ipFailedUsers = new HashMap<>();

        for (LogEvent log : ctx.allLogs) {
            if ("ConsoleLogin".equals(log.getEventName())
                    && "FAILURE".equalsIgnoreCase(log.getEventOutcome())) {
                String ip = log.getSourceIPAddress();
                String user = extractUserName(log);
                if (ip != null && !"Unknown".equals(user)) {
                    ipFailedUsers.computeIfAbsent(ip, k -> new HashSet<>()).add(user);
                }
            }
        }

        for (Map.Entry<String, Set<String>> entry : ipFailedUsers.entrySet()) {
            if (entry.getValue().size() >= BRUTE_FORCE_USER_THRESHOLD) {
                String ip = entry.getKey();
                Set<String> users = entry.getValue();
                // Get the last event from this IP for timestamp
                List<LogEvent> ipEvents = ctx.ipEventMap.getOrDefault(ip, Collections.emptyList());
                String timestamp = ipEvents.isEmpty() ? "" : ipEvents.get(ipEvents.size() - 1).getEventTime();

                alerts.add(createAlert(
                        timestamp, "Brute Force Attack", "HIGH",
                        String.join(", ", users), ip, "ConsoleLogin",
                        "IP " + ip + " attempted failed logins against " + users.size()
                                + " different user accounts: [" + String.join(", ", users)
                                + "]. Possible brute force or credential stuffing attack."
                ));
            }
        }
    }

    /**
     * Multiple IP Login: same user logging in from multiple IPs.
     */
    private void addMultipleIPLoginAlert(DetectionContext ctx, List<Alert> alerts) {
        for (Map.Entry<String, Set<String>> entry : ctx.userIPs.entrySet()) {
            String user = entry.getKey();
            Set<String> ips = entry.getValue();
            if ("Unknown".equals(user) || ips.size() < 2) continue;

            // Only fire if the user actually logged in (ConsoleLogin with SUCCESS)
            boolean hasLogin = false;
            for (LogEvent log : ctx.userEventMap.getOrDefault(user, Collections.emptyList())) {
                if ("ConsoleLogin".equals(log.getEventName())
                        && "SUCCESS".equalsIgnoreCase(log.getEventOutcome())) {
                    hasLogin = true;
                    break;
                }
            }
            if (!hasLogin) continue;

            List<LogEvent> userLogs = ctx.userEventMap.get(user);
            LogEvent last = userLogs.get(userLogs.size() - 1);

            alerts.add(createAlert(
                    last.getEventTime(), "Multiple IP Login", "HIGH",
                    user, String.join(", ", ips), "ConsoleLogin",
                    "User '" + user + "' has been active from " + ips.size()
                            + " different IP addresses: [" + String.join(", ", ips)
                            + "]. This may indicate session hijacking or shared credentials."
            ));
        }
    }

    /**
     * API Burst: more than threshold events per user in a short time window.
     */
    private void addAPIBurstAlert(DetectionContext ctx, List<Alert> alerts) {
        for (Map.Entry<String, List<LogEvent>> entry : ctx.userEventMap.entrySet()) {
            String user = entry.getKey();
            if ("Unknown".equals(user)) continue;

            List<LogEvent> timed = filterWithTime(ctx, entry.getValue());
            if (timed.size() < API_BURST_THRESHOLD) continue;

            timed.sort(Comparator.comparing(ctx::getTime));

            int windowCount = countInWindow(ctx, timed, API_BURST_WINDOW_MINUTES);
            if (windowCount >= API_BURST_THRESHOLD) {
                LogEvent last = timed.get(timed.size() - 1);
                alerts.add(createAlert(
                        last.getEventTime(), "API Burst", "HIGH",
                        user, last.getSourceIPAddress(), "Multiple",
                        "User '" + user + "' generated " + windowCount
                                + " API events within " + API_BURST_WINDOW_MINUTES
                                + " minutes — possible automated tool or compromised credential."
                ));
            }
        }
    }

    /**
     * IAM Reconnaissance: user performing multiple IAM enumeration actions.
     */
    private void addIAMReconnaissanceAlert(DetectionContext ctx, List<Alert> alerts) {
        for (Map.Entry<String, List<LogEvent>> entry : ctx.userEventMap.entrySet()) {
            String user = entry.getKey();
            if ("Unknown".equals(user)) continue;

            Set<String> reconActions = new HashSet<>();
            LogEvent lastRecon = null;

            for (LogEvent log : entry.getValue()) {
                if (log.getEventName() != null && IAM_RECON_EVENTS.contains(log.getEventName())) {
                    reconActions.add(log.getEventName());
                    lastRecon = log;
                }
            }

            if (reconActions.size() >= 3 && lastRecon != null) {
                alerts.add(createAlert(
                        lastRecon.getEventTime(), "IAM Reconnaissance", "HIGH",
                        user, lastRecon.getSourceIPAddress(), "IAM Enumeration",
                        "User '" + user + "' performed " + reconActions.size()
                                + " different IAM enumeration actions: ["
                                + String.join(", ", reconActions)
                                + "]. This may indicate reconnaissance."
                ));
            }
        }
    }

    /**
     * Unusual Login Time: login activity during off-hours (midnight to 5 AM).
     */
    private void addUnusualLoginTimeAlert(DetectionContext ctx, List<Alert> alerts) {
        for (LogEvent log : ctx.allLogs) {
            if (!"ConsoleLogin".equals(log.getEventName())) continue;
            if (!"SUCCESS".equalsIgnoreCase(log.getEventOutcome())) continue;

            LocalDateTime time = ctx.getTime(log);
            if (time == null) continue;

            int hour = time.getHour();
            if (hour >= UNUSUAL_LOGIN_HOUR_START && hour < UNUSUAL_LOGIN_HOUR_END) {
                String user = extractUserName(log);
                alerts.add(createAlert(
                        log.getEventTime(), "Unusual Login Time", "HIGH",
                        user, log.getSourceIPAddress(), "ConsoleLogin",
                        "User '" + user + "' logged in at " + time.toLocalTime()
                                + " (between " + UNUSUAL_LOGIN_HOUR_START + ":00 and "
                                + UNUSUAL_LOGIN_HOUR_END
                                + ":00). Off-hours activity may indicate compromised credentials."
                ));
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //  MEDIUM DETECTIONS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * First-Time Sensitive Action: user performing a sensitive action they haven't done before
     * in the current log batch. Detects anomalous behaviour.
     */
    private void addFirstTimeSensitiveActionAlert(DetectionContext ctx, List<Alert> alerts) {
        // Track which users have performed which sensitive actions
        Map<String, Set<String>> userSensitiveHistory = new HashMap<>();

        for (LogEvent log : ctx.allLogs) {
            String eventName = log.getEventName();
            if (eventName == null || !SENSITIVE_ACTIONS.contains(eventName)) continue;

            String user = extractUserName(log);
            if ("Unknown".equals(user)) continue;

            Set<String> history = userSensitiveHistory.computeIfAbsent(user, k -> new HashSet<>());

            if (history.add(eventName)) {
                // First occurrence of this action for this user
                alerts.add(createAlert(
                        log.getEventTime(), "First-Time Sensitive Action", "MEDIUM",
                        user, log.getSourceIPAddress(), eventName,
                        "User '" + user + "' performed sensitive action '"
                                + eventName + "' for the first time in this session from IP "
                                + log.getSourceIPAddress() + "."
                ));
            }
        }
    }

    /**
     * New IP Detection: a user appears from an IP that no other user has used.
     * Flags unique IPs that are only seen once across all users.
     */
    private void addNewIPDetectionAlert(DetectionContext ctx, List<Alert> alerts) {
        // Count how many users are associated with each IP
        Map<String, Set<String>> ipUsers = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : ctx.userIPs.entrySet()) {
            String user = entry.getKey();
            if ("Unknown".equals(user)) continue;
            for (String ip : entry.getValue()) {
                ipUsers.computeIfAbsent(ip, k -> new HashSet<>()).add(user);
            }
        }

        // IPs used by only one user and appearing once in logs → potentially new
        for (Map.Entry<String, List<LogEvent>> entry : ctx.ipEventMap.entrySet()) {
            String ip = entry.getKey();
            Set<String> usersOnIP = ipUsers.getOrDefault(ip, Collections.emptySet());

            // Only flag if this IP is used by exactly one user and appears very rarely
            if (usersOnIP.size() == 1 && entry.getValue().size() == 1) {
                LogEvent log = entry.getValue().get(0);
                String user = extractUserName(log);
                if ("Unknown".equals(user)) continue;

                alerts.add(createAlert(
                        log.getEventTime(), "New IP Detection", "MEDIUM",
                        user, ip, log.getEventName(),
                        "User '" + user + "' was seen from IP " + ip
                                + " for the first time. This IP has no prior activity in the current dataset."
                ));
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //  UTILITY METHODS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * Extracts username from a LogEvent safely.
     */
    private static String extractUserName(LogEvent log) {
        if (log.getUserIdentity() != null && log.getUserIdentity().getUserName() != null
                && !log.getUserIdentity().getUserName().isEmpty()) {
            return log.getUserIdentity().getUserName();
        }
        return "Unknown";
    }

    /**
     * Detects if a LogEvent is from the root account.
     */
    private static boolean isRootAccount(LogEvent log) {
        if (log.getUserIdentity() == null) return false;
        String userName = log.getUserIdentity().getUserName();
        String type = log.getUserIdentity().getType();
        return "Root".equalsIgnoreCase(type)
                || "root".equalsIgnoreCase(userName)
                || "AWS::Root".equals(userName);
    }

    /**
     * Parses an event time string into a LocalDateTime using multiple formats.
     */
    private static LocalDateTime parseTime(String timeStr) {
        if (timeStr == null || timeStr.isEmpty()) return null;
        for (DateTimeFormatter fmt : TIME_FORMATTERS) {
            try {
                return LocalDateTime.parse(timeStr, fmt);
            } catch (DateTimeParseException ignored) {
                // Try next format
            }
        }
        return null;
    }

    /**
     * Filters a list of events to only those with successfully parsed times.
     */
    private List<LogEvent> filterWithTime(DetectionContext ctx, List<LogEvent> events) {
        List<LogEvent> result = new ArrayList<>();
        for (LogEvent log : events) {
            if (ctx.getTime(log) != null) {
                result.add(log);
            }
        }
        return result;
    }

    /**
     * Sliding window count: returns the max number of events within the given window (minutes).
     * Events MUST be pre-sorted by time.
     */
    private int countInWindow(DetectionContext ctx, List<LogEvent> sorted, int windowMinutes) {
        int maxCount = 0;
        int start = 0;

        for (int end = 0; end < sorted.size(); end++) {
            LocalDateTime endTime = ctx.getTime(sorted.get(end));
            if (endTime == null) continue;

            // Advance start pointer to maintain window
            while (start < end) {
                LocalDateTime startTime = ctx.getTime(sorted.get(start));
                if (startTime != null
                        && ChronoUnit.MINUTES.between(startTime, endTime) > windowMinutes) {
                    start++;
                } else {
                    break;
                }
            }
            maxCount = Math.max(maxCount, end - start + 1);
        }
        return maxCount;
    }

    /**
     * Factory method for creating alerts with a generated UUID.
     */
    private Alert createAlert(String timestamp, String ruleName, String severity,
                              String user, String ip, String eventType, String description) {
        return new Alert(
                UUID.randomUUID().toString(),
                timestamp, ruleName, severity, user, ip, eventType, description
        );
    }
}