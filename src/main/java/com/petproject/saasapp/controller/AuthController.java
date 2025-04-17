package com.petproject.saasapp.controller;

import com.petproject.saasapp.model.entity.User;
import com.petproject.saasapp.service.AuthService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public String register(@RequestParam("email") String email, @RequestParam("password") String password) {
        return authService.register(email, password);
    }

    @PostMapping("/login")
    public String login(@RequestParam("email") String email, @RequestParam("password") String password) {
        return authService.login(email, password);
    }
    @GetMapping("/get-current-user")
    public User getCurrentUser() {
        return authService.getCurrentUser();
    }
}
