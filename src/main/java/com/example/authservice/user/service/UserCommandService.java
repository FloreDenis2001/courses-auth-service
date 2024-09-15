package com.example.authservice.user.service;


import com.example.authservice.user.dto.UpdateRequest;
import com.example.authservice.user.dto.UserDTO;
import org.springframework.stereotype.Service;

@Service
public interface UserCommandService {

    void addUser(UserDTO userDTO);


    void updateUser(String email, UpdateRequest updateRequest);

    void deleteUser(String email);

    void updateProfileUrl(String email, String profileUrl);
}

