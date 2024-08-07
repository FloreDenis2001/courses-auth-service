package com.example.authservice.system.security;


import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum UserPermission {
    USER_READ("user:read"),
    USER_WRITE("user:write");

    private final String permission;

}
