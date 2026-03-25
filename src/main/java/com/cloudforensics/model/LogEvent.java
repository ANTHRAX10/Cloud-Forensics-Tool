package com.cloudforensics.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * Represents one log entry fetched from the JSON log file.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LogEvent {
    private String timestamp;
    private String severity;
    private String eventType;
    private String user;
    private String resource;
    private String ip;
    private String status;
}
