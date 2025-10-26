package edu.nu.owaspapivulnlab.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

// --- FIX 8: Error Handling (Global Handler) ---
@RestControllerAdvice
public class GlobalErrorHandler {

    // --- FIX 8: Secure Logging ---
    // Use a logger to write full error details to the server console/file
    private static final Logger log = LoggerFactory.getLogger(GlobalErrorHandler.class);

    /**
     * Handles validation errors from @Valid (Task 9).
     * Returns a 400 Bad Request with a clear message.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDto> handleValidationExceptions(MethodArgumentNotValidException ex) {
        // Log the full details for debugging
        log.warn("Validation failed: {}", ex.getMessage());

        // Create a user-friendly message
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));

        ErrorResponseDto errorDto = new ErrorResponseDto(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                message
        );
        return new ResponseEntity<>(errorDto, HttpStatus.BAD_REQUEST);
    }

    /**
     * Handles security authorization failures (Task 3).
     * Returns a 403 Forbidden.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponseDto> handleAccessDenied(AccessDeniedException ex) {
        // Log the specific resource violation
        log.warn("Access denied: {}", ex.getMessage());

        ErrorResponseDto errorDto = new ErrorResponseDto(
                HttpStatus.FORBIDDEN.value(),
                "Forbidden",
                "You do not have permission to access this resource."
        );
        return new ResponseEntity<>(errorDto, HttpStatus.FORBIDDEN);
    }

    /**
     * Catch-all handler for any other unexpected errors.
     * Returns a generic 500 Internal Server Error.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDto> handleGenericException(Exception ex) {
        // --- FIX 8: Secure Logging ---
        // Log the full stack trace on the server-side
        log.error("An unexpected error occurred", ex);

        // --- FIX 8: Error Handling ---
        // Return a generic, non-leaky message to the client
        ErrorResponseDto errorDto = new ErrorResponseDto(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "An unexpected error occurred. Please contact support."
        );
        return new ResponseEntity<>(errorDto, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}