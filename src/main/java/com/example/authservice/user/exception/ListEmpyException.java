package com.example.authservice.user.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class ListEmpyException extends RuntimeException {
    public ListEmpyException(String message) {
        super(message);
    }
}
