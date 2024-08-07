package com.example.authservice.user.dto;

public record RegisterResponse(String token, String firstName, String lastName, String phoneNumber, String email, boolean active) {
}
