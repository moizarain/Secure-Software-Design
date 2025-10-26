package edu.nu.owaspapivulnlab.web;

import java.time.Instant;

// This DTO ensures a consistent, non-leaky error message is sent to the client.
public class ErrorResponseDto {
    private int status;
    private String error;
    private String message;
    private Instant timestamp;

    public ErrorResponseDto(int status, String error, String message) {
        this.status = status;
        this.error = error;
        this.message = message;
        this.timestamp = Instant.now();
    }

    // Getters
    public int getStatus() { return status; }
    public String getError() { return error; }
    public String getMessage() { return message; }
    public Instant getTimestamp() { return timestamp; }
}