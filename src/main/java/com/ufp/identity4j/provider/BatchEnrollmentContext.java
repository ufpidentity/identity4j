package com.ufp.identity4j.provider;

import java.io.OutputStream;

/**
 * A context to hold objects related to batch enrollment. Batch enrollment is used for very fast enrollment of existing users. 
 * The output stream is used to write out the actual enrollment parameters and the thread object is available to join on until 
 * the thread has finished.
 */
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