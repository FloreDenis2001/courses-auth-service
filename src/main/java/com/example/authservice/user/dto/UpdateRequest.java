package com.example.authservice.user.dto;

public record UpdateRequest(String firstName, String lastName, String phoneNumber, String email, String currentPassword, String newPassword) {
}
