package com.example.authservice.utils;
public class Utils {
    public static final String USERNAME_ALREADY_EXISTS = "Username already exists";
    public static final String EMAIL_ALREADY_EXISTS = "Email already exists";
    public static final String NO_USER_FOUND_BY_USERNAME = "No user found by username: ";
    public static final String FOUND_USER_BY_USERNAME = "Returning found user by username: ";
    public static final String NO_USER_FOUND_BY_EMAIL = "No user found for email: ";
    public static final long EXPIRATION_TIME = 432_000_000;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String JWT_TOKEN_EXPIRATION_HEADER = "Jwt-Token expiration time";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String MY_CODE = "MyCode";
    public static final String GET_MY_CODE_LLC = "MyCode, LLC";
    public static final String  ADMINISTRATION = "Library Manager ";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to log in to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    public static final String[] PUBLIC_URLS = {"/swagger-ui.html","/swagger-ui/**","/v3/**","/server/api/v1/test","/server/api/v1/login","/server/api/v1/verifyToken","/server/api/v1/register" , "/server/api/v1/account/activation/**", "/server/api/v1/password/reset/**", "/server/api/v1/cloud/b2/upload","/actuator/**"};
}

