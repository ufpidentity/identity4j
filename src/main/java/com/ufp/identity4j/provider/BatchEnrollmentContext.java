package com.ufp.identity4j.provider;

import java.io.OutputStream;

public class BatchEnrollmentContext {
    private OutputStream outputStream;
    private Thread thread;

    public BatchEnrollmentContext(OutputStream outputStream, Thread thread) {
        this.outputStream = outputStream;
        this.thread = thread;
    }
    
    public OutputStream getOutputStream() {
        return outputStream;
    }

    public Thread getThread() {
        return thread;
    }
}