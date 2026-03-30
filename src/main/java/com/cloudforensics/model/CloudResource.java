package com.cloudforensics.model;

public class CloudResource {
    private String resourceName;
    private String resourceType;

    public CloudResource() {}

    public CloudResource(String resourceName, String resourceType) {
        this.resourceName = resourceName;
        this.resourceType = resourceType;
    }

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public String getResourceType() {
        return resourceType;
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }
}
