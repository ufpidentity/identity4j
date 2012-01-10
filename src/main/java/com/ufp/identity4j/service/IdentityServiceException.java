package com.ufp.identity4j.service;

import com.ufp.identity4j.data.Result;

/**
 * Custom exception class which allows the {@link com.ufp.identity4j.data.Result} to be propagated up the call-stack
 */
public class IdentityServiceException extends Exception {
    private Result result;

    public IdentityServiceException(Result result, Throwable cause) {
        super(result.getMessage(), cause);
        this.result = result;
    }

    public IdentityServiceException(Result result) {
        super(result.getMessage());
        this.result = result;
    }

    public Result getResult() {
        return result;
    }
}