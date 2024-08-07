package com.example.authservice.user.repo;


import com.example.authservice.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepo  extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
}
