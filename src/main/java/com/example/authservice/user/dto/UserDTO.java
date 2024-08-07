package com.example.authservice.user.dto;


import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record UserDTO(String firstName, String lastName, String phoneNumber, String email, String password, LocalDateTime createdAt, boolean active) {
    public UserDTO(String firstName, String lastName, String phoneNumber, String email, String password, LocalDateTime createdAt, boolean active) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.phoneNumber = phoneNumber;
        this.email = email;
        this.password = password;
        this.createdAt = (createdAt == null) ? LocalDateTime.now() : createdAt;
        this.active = active || true;
    }
}
