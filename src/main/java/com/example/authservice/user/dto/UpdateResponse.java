package com.example.authservice.user.dto;

import com.example.authservice.system.security.UserRole;

public record UpdateResponse(String firstName,
                             String lastName,
                             String phoneNumber,
                             String email,
                             String profileUrl,
                             UserRole userRole,
                             boolean active ) {
}
