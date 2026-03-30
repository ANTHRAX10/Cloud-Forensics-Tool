package com.cloudforensics.util;

import com.cloudforensics.model.CloudResource;
import com.cloudforensics.model.LogEvent;
import com.cloudforensics.model.UserIdentity;

import java.util.Map;

public class CloudLogParser {

    @SuppressWarnings("unchecked")
    public static LogEvent parseLog(Map<String, Object> rawLog) {
        LogEvent event = new LogEvent();
        
        // Parse time
        if (rawLog.containsKey("eventTime")) {
            event.setEventTime((String) rawLog.get("eventTime"));
        } else if (rawLog.containsKey("timestamp")) {
            event.setEventTime((String) rawLog.get("timestamp"));
        }
        
        // Parse event name
        if (rawLog.containsKey("eventName")) {
            event.setEventName((String) rawLog.get("eventName"));
        } else if (rawLog.containsKey("eventType")) {
            event.setEventName((String) rawLog.get("eventType"));
        }
        
        // Parse identity
        UserIdentity identity = new UserIdentity();
        if (rawLog.containsKey("userIdentity") && rawLog.get("userIdentity") instanceof Map) {
            Map<String, Object> userIdentityMap = (Map<String, Object>) rawLog.get("userIdentity");
            identity.setUserName((String) userIdentityMap.get("userName"));
            identity.setType((String) userIdentityMap.get("type"));
        } else if (rawLog.containsKey("user")) {
            identity.setUserName((String) rawLog.get("user"));
            identity.setType("IAMUser");
        }
        event.setUserIdentity(identity);
        
        // Parse IP address
        if (rawLog.containsKey("sourceIPAddress")) {
            event.setSourceIPAddress((String) rawLog.get("sourceIPAddress"));
        } else if (rawLog.containsKey("ip")) {
            event.setSourceIPAddress((String) rawLog.get("ip"));
        }
        
        // Parse resource
        CloudResource resource = new CloudResource();
        if (rawLog.containsKey("resource") && rawLog.get("resource") instanceof Map) {
            Map<String, Object> resourceMap = (Map<String, Object>) rawLog.get("resource");
            resource.setResourceName((String) resourceMap.get("resourceName"));
            resource.setResourceType((String) resourceMap.get("resourceType"));
        } else if (rawLog.containsKey("resource") && rawLog.get("resource") instanceof String) {
            resource.setResourceName((String) rawLog.get("resource"));
            resource.setResourceType("Unknown");
        }
        event.setResource(resource);
        
        // Parse event outcome
        if (rawLog.containsKey("eventOutcome")) {
            event.setEventOutcome((String) rawLog.get("eventOutcome"));
        } else if (rawLog.containsKey("status")) {
            event.setEventOutcome((String) rawLog.get("status"));
        }
        
        // Parse provider & region
        if (rawLog.containsKey("cloudProvider")) {
            event.setCloudProvider((String) rawLog.get("cloudProvider"));
        } else {
            event.setCloudProvider("AWS"); // Default to AWS for legacy compatibility
        }
        
        if (rawLog.containsKey("region")) {
            event.setRegion((String) rawLog.get("region"));
        } else {
            event.setRegion("us-east-1");
        }
        
        // Severity is specifically NOT extracted - it will be added by DetectionRuleService
        
        return event;
    }
}
