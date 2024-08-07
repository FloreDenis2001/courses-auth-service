package com.example.authservice.user.service;


import com.example.authservice.user.model.User;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public interface UserQuerryService {
    Optional<User> findByEmail(String email);
}

