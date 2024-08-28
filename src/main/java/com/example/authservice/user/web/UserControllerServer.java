package com.example.authservice.user.web;

import com.example.authservice.intercom.b2.B2S3Service;
import com.example.authservice.user.dto.LoginRequest;
import com.example.authservice.user.dto.LoginResponse;
import com.example.authservice.user.dto.RegisterResponse;
import com.example.authservice.user.dto.UserDTO;
import com.example.authservice.user.model.User;
import com.example.authservice.user.service.UserCommandService;
import com.example.authservice.user.service.UserQuerryService;
import com.example.authservice.system.jwt.JWTTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.UUID;

import static com.example.authservice.utils.Utils.JWT_TOKEN_HEADER;

@RestController
@CrossOrigin
@RequestMapping("/server/api/v1/")
@AllArgsConstructor
public class UserControllerServer {

    private final UserCommandService userCommandService;
    private final UserQuerryService userQuerryService;
    private final AuthenticationManager authenticationManager;
    private final JWTTokenProvider jwtTokenProvider;
    private final B2S3Service b2S3Service;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest user) {
        authenticate(user.email(), user.password());
        User loginUser = userQuerryService.findByEmail(user.email()).get();
        User userPrincipal = getUser(loginUser);

        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        LoginResponse loginResponse = new LoginResponse(
                jwtHeader.getFirst(JWT_TOKEN_HEADER),
                userPrincipal.getFirstName(),
                userPrincipal.getLastName(),
                userPrincipal.getPhoneNumber(),
                userPrincipal.getEmail(),
                userPrincipal.isActive(),
                userPrincipal.getProfileUrl() ,
                userPrincipal.getUserRole()
        );
        return new ResponseEntity<>(loginResponse, jwtHeader, HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody UserDTO userDTO) {
        this.userCommandService.addUser(userDTO);
        User userPrincipal = userQuerryService.findByEmail(userDTO.email()).get();
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        RegisterResponse registerResponse = new RegisterResponse(
                jwtHeader.getFirst(JWT_TOKEN_HEADER),
                userPrincipal.getFirstName(),
                userPrincipal.getLastName(),
                userPrincipal.getPhoneNumber(),
                userPrincipal.getEmail(),
                userPrincipal.isActive(),
                userPrincipal.getProfileUrl(),
                userPrincipal.getUserRole()
        );
        authenticate(userDTO.email(), userDTO.password());
        return new ResponseEntity<>(registerResponse, jwtHeader, HttpStatus.OK);
    }

    @PostMapping("/updateProfilePicture")
    @PreAuthorize( "hasRole('ROLE_CLIENT') or hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> updateProfilePicture(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("File is empty.");
        }


        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        User currentUser = userQuerryService.findByEmail(authentication.getName()).get();

        File convertedFile = null;
        try {
            convertedFile = convertMultiPartToFile(file);
            String fileName = UUID.randomUUID() + "_" + file.getOriginalFilename();
            String fileUrl = b2S3Service.uploadFile(convertedFile, fileName);


            userCommandService.updateProfileUrl(currentUser.getEmail(), fileUrl);

            return ResponseEntity.ok(fileUrl);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload file.");
        } finally {
            if (convertedFile != null && convertedFile.exists()) {
                if (!convertedFile.delete()) {
                    System.err.println("Failed to delete temporary file");
                }
            }
        }
    }


    private File convertMultiPartToFile(MultipartFile file) throws IOException {
        File convFile = File.createTempFile(UUID.randomUUID().toString(), "." + getFileExtension(file.getOriginalFilename()));
        try (FileOutputStream fos = new FileOutputStream(convFile)) {
            fos.write(file.getBytes());
        }
        return convFile;
    }

    private String getFileExtension(String filename) {
        String[] parts = filename.split("\\.");
        return parts.length > 1 ? parts[parts.length - 1] : "";
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }

    private HttpHeaders getJwtHeader(User user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJWTToken(user));
        return headers;
    }

    private User getUser(User loginUser) {
        User userPrincipal = new User();
        userPrincipal.setEmail(loginUser.getEmail());
        userPrincipal.setPassword(loginUser.getPassword());
        userPrincipal.setUserRole(loginUser.getUserRole());
        userPrincipal.setActive(loginUser.isActive());
        userPrincipal.setFirstName(loginUser.getFirstName());
        userPrincipal.setLastName(loginUser.getLastName());
        userPrincipal.setPhoneNumber(loginUser.getPhoneNumber());
        userPrincipal.setRegisteredAt(loginUser.getRegisteredAt());
        userPrincipal.setProfileUrl(loginUser.getProfileUrl());
        userPrincipal.setCreatedAt(loginUser.getCreatedAt());
        return userPrincipal;
    }
}
