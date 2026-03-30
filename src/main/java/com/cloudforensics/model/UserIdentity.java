package com.cloudforensics.model;

public class UserIdentity {
    private String userName;
    private String type;

    public UserIdentity() {}

    public UserIdentity(String userName, String type) {
        this.userName = userName;
        this.type = type;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
