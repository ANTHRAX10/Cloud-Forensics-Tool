package com.cloudforensics.model;

public class CloudResource {

    private String resourceName;
    private String resourceType;

    public CloudResource() {}

    public CloudResource(String resourceName, String resourceType) {
        this.resourceName = resourceName;
        this.resourceType = resourceType;
    }

    /**
     * Safe resource name (used in timeline)
     */
    public String getResourceName() {
        if (resourceName != null && !resourceName.isEmpty()) {
            return resourceName.trim();
        }
        return "UNKNOWN_RESOURCE";
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    /**
     * Safe resource type
     */
    public String getResourceType() {
        if (resourceType != null && !resourceType.isEmpty()) {
            return resourceType.trim();
        }
        return "UNKNOWN_TYPE";
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }
}