package com.cloudforensics.model;

/**
 * A single MITRE ATT&CK technique detected and mapped during report generation.
 * The mapping is driven by the configurable mitre-mapping.json resource file.
 */
public class MitreTechnique {

    /** MITRE technique identifier (e.g. "T1078"). */
    private String techniqueId;

    /** Human-readable technique name (e.g. "Valid Accounts"). */
    private String techniqueName;

    /** The raw event type that triggered this mapping (e.g. "ConsoleLogin"). */
    private String triggeringEventType;

    /** MITRE tactic category (e.g. "Initial Access", "Privilege Escalation"). */
    private String tactic;

    public MitreTechnique() {}

    public MitreTechnique(String techniqueId, String techniqueName,
                          String triggeringEventType, String tactic) {
        this.techniqueId = techniqueId;
        this.techniqueName = techniqueName;
        this.triggeringEventType = triggeringEventType;
        this.tactic = tactic;
    }

    public String getTechniqueId() { return techniqueId; }
    public void setTechniqueId(String techniqueId) { this.techniqueId = techniqueId; }

    public String getTechniqueName() { return techniqueName; }
    public void setTechniqueName(String techniqueName) { this.techniqueName = techniqueName; }

    public String getTriggeringEventType() { return triggeringEventType; }
    public void setTriggeringEventType(String triggeringEventType) { this.triggeringEventType = triggeringEventType; }

    public String getTactic() { return tactic; }
    public void setTactic(String tactic) { this.tactic = tactic; }
}
