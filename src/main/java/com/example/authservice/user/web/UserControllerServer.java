package com.example.authservice.user.web;
import com.example.authservice.system.jwt.JWTTokenProvider;
import com.example.authservice.user.dto.LoginResponse;
import com.example.authservice.user.dto.RegisterResponse;
import com.example.authservice.user.dto.UserDTO;
import com.example.authservice.user.model.User;
import com.example.authservice.user.service.UserCommandService;
import com.example.authservice.user.service.UserQuerryService;
import lombok.AllArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import org.springframework.http.HttpHeaders;

import static com.example.authservice.utils.Utils.JWT_TOKEN_HEADER;
import static org.springframework.http.HttpStatus.OK;


@RestController
@CrossOrigin
@RequestMapping("/server/api/v1/")
@AllArgsConstructor
public class UserControllerServer {

    private UserCommandService userCommandService;
    private UserQuerryService userQuerryService;
    private AuthenticationManager authenticationManager;
    private JWTTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody UserDTO user) {
        authenticate(user.email(),user.password());
        User loginUser = userQuerryService.findByEmail(user.email()).get();
        User userPrincipal = getUser(loginUser);

        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        LoginResponse loginResponse= new LoginResponse(jwtHeader.getFirst(JWT_TOKEN_HEADER), userPrincipal.getFirstName(), userPrincipal.getLastName(), userPrincipal.getPhoneNumber(), userPrincipal.getEmail(), userPrincipal.isActive());
        return new ResponseEntity<>(loginResponse,jwtHeader,OK);
    }

    private static User getUser(User loginUser) {
        User userPrincipal = new User();
        userPrincipal.setEmail(loginUser.getEmail());
        userPrincipal.setPassword(loginUser.getPassword());
        userPrincipal.setUserRole(loginUser.getUserRole());
        userPrincipal.setActive(loginUser.isActive());
        userPrincipal.setFirstName(loginUser.getFirstName());
        userPrincipal.setLastName(loginUser.getLastName());
        userPrincipal.setPhoneNumber(loginUser.getPhoneNumber());
        userPrincipal.setRegisteredAt(loginUser.getRegisteredAt());
        userPrincipal.setCreatedAt(loginUser.getCreatedAt());
        return userPrincipal;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> addStudent(@RequestBody UserDTO user){
        this.userCommandService.addUser(user);
        User userPrincipal = userQuerryService.findByEmail(user.email()).get();
        HttpHeaders jwtHeader=getJwtHeader(userPrincipal);
        RegisterResponse registerResponse= new RegisterResponse(jwtHeader.getFirst(JWT_TOKEN_HEADER), userPrincipal.getFirstName(), userPrincipal.getLastName(), userPrincipal.getPhoneNumber(), userPrincipal.getEmail(), userPrincipal.isActive());
        authenticate(user.email(), user.password());
        return new ResponseEntity<>(registerResponse,jwtHeader,OK);
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }

    private HttpHeaders getJwtHeader(User user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJWTToken(user));
        return headers;
    }
}
