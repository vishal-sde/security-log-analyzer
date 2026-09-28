package com.application.security_log_analyzer.logs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger rejectLog = LoggerFactory.getLogger("log-rejects");

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex){
        String errors = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .collect(Collectors.joining(";"));
        rejectLog.warn("Rejected log event - {}",errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("status","rejected","errors",errors));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String,Object>> handleMalformed(HttpMessageNotReadableException he){
        rejectLog.warn("Rejected malformed JSON or unknown eventType");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("status","rejected","errors","Malformed JSON or invalid field value"));
    }
}