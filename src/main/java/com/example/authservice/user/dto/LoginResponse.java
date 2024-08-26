package com.example.authservice.user.dto;


import com.example.authservice.system.security.UserRole;

public record LoginResponse(String token, String firstName, String lastName, String phoneNumber, String email, boolean active , UserRole userRole) {
}