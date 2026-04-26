package com.cloudforensics.service;

import com.cloudforensics.model.LogEvent;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class TimelineService {

    public List<AttackTimelineResponse> processTimeline(List<LogEvent> logs) {
        List<List<LogEvent>> chains = buildChains(logs);
        List<AttackTimelineResponse> responses = new ArrayList<>();

        for (List<LogEvent> chain : chains) {
            if (chain.size() < 2) continue;

            String primaryUser = chain.get(0).getUserIdentity() != null ? chain.get(0).getUserIdentity().getUserName() : "Unknown";
            
            List<Node> nodes = computeDeltas(chain);
            Graph graph = buildGraph(nodes);
            String attackType = classifyAttack(nodes);

            responses.add(new AttackTimelineResponse(UUID.randomUUID().toString(), primaryUser, attackType, graph));
        }
        return responses;
    }

    public String mapToAttackPhase(String eventName) {
        if (eventName == null) return "Normal Activity";
        switch (eventName) {
            case "ConsoleLogin": return "Initial Access";
            case "AttachUserPolicy":
            case "PutUserPolicy": return "Privilege Escalation";
            case "CreateAccessKey": return "Persistence";
            case "ListUsers":
            case "ListRoles": return "Discovery";
            case "GetObject": return "Exfiltration";
            case "StopLogging":
            case "DeleteTrail": return "Defense Evasion";
            default: return "Normal Activity";
        }
    }

    public List<List<LogEvent>> buildChains(List<LogEvent> logs) {
        logs.sort(Comparator.comparing(this::parseTime));
        List<List<LogEvent>> chains = new ArrayList<>();

        for (LogEvent log : logs) {
            LocalDateTime time = parseTime(log);
            if (time == null) continue;

            boolean added = false;
            for (int i = chains.size() - 1; i >= 0; i--) {
                List<LogEvent> chain = chains.get(i);
                LogEvent lastEvent = chain.get(chain.size() - 1);

                if (ChronoUnit.MINUTES.between(parseTime(lastEvent), time) > 10) continue;

                if (isSameUserOrIp(log, lastEvent)) {
                    chain.add(log);
                    added = true;
                    break;
                }
            }
            if (!added) {
                List<LogEvent> newChain = new ArrayList<>();
                newChain.add(log);
                chains.add(newChain);
            }
        }
        return chains;
    }

    public List<Node> computeDeltas(List<LogEvent> chain) {
        List<Node> nodes = new ArrayList<>();
        if (chain.isEmpty()) return nodes;

        LocalDateTime startTime = parseTime(chain.get(0));
        LocalDateTime prevTime = startTime;

        for (LogEvent log : chain) {
            LocalDateTime currTime = parseTime(log);

            Node node = new Node();
            node.id = UUID.randomUUID().toString();
            node.eventName = log.getEventName();
            node.phase = mapToAttackPhase(log.getEventName());
            node.timestamp = log.getEventTime();
            node.severity = log.getSeverity() != null ? log.getSeverity() : "LOW";
            node.ip = log.getSourceIPAddress();
            
            node.deltaMinutes = ChronoUnit.MINUTES.between(prevTime, currTime);
            node.deltaFromStart = ChronoUnit.MINUTES.between(startTime, currTime);

            nodes.add(node);
            prevTime = currTime;
        }
        return nodes;
    }

    public Graph buildGraph(List<Node> nodes) {
        List<Edge> edges = new ArrayList<>();
        
        for (int i = 0; i < nodes.size(); i++) {
            Node curr = nodes.get(i);

            // Sequential edge
            if (i < nodes.size() - 1) {
                edges.add(new Edge(curr.id, nodes.get(i + 1).id, "SEQUENTIAL"));
            }

            // Causal edge
            for (int j = i + 1; j < nodes.size(); j++) {
                Node next = nodes.get(j);
                if (!curr.phase.equals("Normal Activity") && !next.phase.equals("Normal Activity") && !curr.phase.equals(next.phase)) {
                    edges.add(new Edge(curr.id, next.id, "CAUSAL"));
                    break;
                }
            }
        }
        return new Graph(nodes, edges);
    }

    public String classifyAttack(List<Node> nodes) {
        Set<String> phases = nodes.stream().map(n -> n.phase).collect(Collectors.toSet());
        
        boolean failedLogin = nodes.stream().anyMatch(n -> "ConsoleLogin".equals(n.eventName));
        boolean initialAccess = phases.contains("Initial Access");
        boolean privEsc = phases.contains("Privilege Escalation");
        boolean exfil = phases.contains("Exfiltration");
        boolean recon = phases.contains("Discovery");
        boolean persistence = phases.contains("Persistence");

        if (failedLogin && initialAccess && privEsc && exfil) return "Full Attack Lifecycle";
        if (recon && privEsc && persistence) return "Privilege Escalation Attack";
        if (exfil) return "Data Exfiltration Event";
        
        return "Suspicious Activity Pattern";
    }

    private boolean isSameUserOrIp(LogEvent e1, LogEvent e2) {
        String u1 = e1.getUserIdentity() != null ? e1.getUserIdentity().getUserName() : "";
        String u2 = e2.getUserIdentity() != null ? e2.getUserIdentity().getUserName() : "";
        boolean sameUser = !u1.isEmpty() && u1.equals(u2);
        
        String ip1 = e1.getSourceIPAddress() != null ? e1.getSourceIPAddress() : "";
        String ip2 = e2.getSourceIPAddress() != null ? e2.getSourceIPAddress() : "";
        boolean sameIp = !ip1.isEmpty() && ip1.equals(ip2);
        
        return sameUser || sameIp;
    }

    private LocalDateTime parseTime(LogEvent log) {
        if (log.getEventTime() == null) return null;
        try {
            return LocalDateTime.parse(log.getEventTime(), DateTimeFormatter.ISO_DATE_TIME);
        } catch (Exception e) {
            return null; // fallback for badly formatted logs
        }
    }

    // --- DTO Classes ---

    public static class AttackTimelineResponse {
        public String chainId;
        public String user;
        public String attackType;
        public Graph graph;
        
        public AttackTimelineResponse(String chainId, String user, String attackType, Graph graph) {
            this.chainId = chainId; this.user = user; this.attackType = attackType; this.graph = graph;
        }
    }

    public static class Graph {
        public List<Node> nodes;
        public List<Edge> edges;
        
        public Graph(List<Node> nodes, List<Edge> edges) {
            this.nodes = nodes; this.edges = edges;
        }
    }

    public static class Node {
        public String id, eventName, phase, timestamp, severity, ip;
        public long deltaMinutes, deltaFromStart;
    }

    public static class Edge {
        public String from, to, relation;
        
        public Edge(String from, String to, String relation) {
            this.from = from; this.to = to; this.relation = relation;
        }
    }
}
