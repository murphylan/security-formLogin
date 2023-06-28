package com.academy.securityformLogin.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
  @GetMapping("/hello")
  public String hello() {
    return "hello world";
  }

  @GetMapping("/me")
  public Authentication getMe(Authentication authentication) {
    return authentication;
  }
}
