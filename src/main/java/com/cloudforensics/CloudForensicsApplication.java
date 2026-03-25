package com.cloudforensics;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Cloud Forensics Investigation Platform backend.
 * Boots the Spring application on port 8080 (default).
 */
@SpringBootApplication
public class CloudForensicsApplication {
    public static void main(String[] args) {
        SpringApplication.run(CloudForensicsApplication.class, args);
    }
}
