package com.ufp.identity4j.service;

import com.ufp.identity4j.data.Result;

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