package com.ufp.identity4j.service;

public class IdentityServiceException extends Exception {
    public IdentityServiceException(String message, Throwable cause) {
        super(message, cause);
    }

    public IdentityServiceException(String message) {
        super(message);
    }
}