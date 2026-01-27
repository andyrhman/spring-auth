package com.myspring.spring_auth.util;

public class InvalidRequestException extends RuntimeException {
    public InvalidRequestException(String msg) {
        super(msg);
    }
}