package com.example.authservice.user.dto;




public record LoginResponse(String token, String firstName, String lastName, String phoneNumber, String email,  boolean active) {
}