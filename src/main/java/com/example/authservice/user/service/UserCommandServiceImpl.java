package com.example.authservice.user.service;

import com.example.authservice.system.security.UserRole;
import com.example.authservice.user.dto.UserDTO;
import com.example.authservice.user.exception.UserAlreadyExistsException;
import com.example.authservice.user.exception.UserNotFoundException;
import com.example.authservice.user.model.User;
import com.example.authservice.user.repo.UserRepo;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@Transactional
@AllArgsConstructor
public class UserCommandServiceImpl implements UserCommandService {
    private UserRepo userRepo;
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public void addUser(UserDTO userDTO) {

        Optional<User> user = userRepo.findByEmail(userDTO.email());
        if (user.isEmpty()) {
            User x = User.builder()
                    .email(userDTO.email())
                    .firstName(userDTO.firstName())
                    .lastName(userDTO.lastName())
                    .phoneNumber(userDTO.phoneNumber())
                    .password(passwordEncoder.encode(userDTO.password()))
                    .registeredAt(LocalDateTime.now())
                    .createdAt(userDTO.createdAt())
                    .active(true)
                    .userRole(UserRole.CLIENT)
                    .build();
            userRepo.saveAndFlush(x);
        } else {
            throw new UserAlreadyExistsException("User with email " + userDTO.email() + " already exists");
        }
    }

    @Override
    public void updateUser(String email, UserDTO userDTO) {

        Optional<User> user = userRepo.findByEmail(email);
        if (user.isPresent()) {
            User x = user.get();
            x.setEmail(userDTO.email());
            x.setFirstName(userDTO.firstName());
            x.setLastName(userDTO.lastName());
            x.setPhoneNumber(userDTO.phoneNumber());
            x.setPassword(userDTO.password());
            userRepo.saveAndFlush(x);
        } else {
            throw new UserNotFoundException("User with email " + email + " not found");
        }

    }

    @Override
    public void deleteUser(String email) {

        Optional<User> user = userRepo.findByEmail(email);
        if (user.isPresent()) {
            userRepo.delete(user.get());
        } else {
            throw new UserNotFoundException("User with email " + email + " not found");
        }

    }
}
