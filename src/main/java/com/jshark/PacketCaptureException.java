package com.jshark;

public class PacketCaptureException extends RuntimeException
{
    public PacketCaptureException(String message) {
        super(message);
    }
    
    public PacketCaptureException(String message, Throwable cause) {
        super(message, cause);
    }
}
