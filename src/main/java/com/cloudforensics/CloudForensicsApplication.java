package com.cloudforensics;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Cloud Forensics Investigation Tool — Spring Boot entry point.
 *
 * @EnableAsync activates Spring's asynchronous task executor, which is required
 * for @Async report generation in ForensicReportService.
 */
@SpringBootApplication
@EnableAsync
public class CloudForensicsApplication {
    public static void main(String[] args) {
        SpringApplication.run(CloudForensicsApplication.class, args);
    }
}