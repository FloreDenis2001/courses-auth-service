package com.example.authservice.user.service;

import com.example.authservice.user.exception.ListEmpyException;
import com.example.authservice.user.model.User;
import com.example.authservice.user.repo.UserRepo;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserQuerryServiceImpl implements UserQuerryService {
    UserRepo userRepo;


    public UserQuerryServiceImpl(UserRepo userRepo) {
        this.userRepo = userRepo;
    }


    @Override
    public Optional<User> findByEmail(String email) {
        Optional<User> user = userRepo.findByEmail(email);
        if (user.isPresent()) {
            return user;
        } else {
            throw new ListEmpyException("User with email " + email + " not found");
        }
    }
}
