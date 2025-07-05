package com.example.securityDemo;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping("/hello")
    public String sayHello(){
        return "Hello";
    }

    @GetMapping("/user")
    public String userEndPoint(){
        return "Hello User";
    }

    @PreAuthorize("hasRole('AdminRole')")
    @GetMapping("/admin")
    public String adminEndPoint(){
        return "Hello admin";
    }
}
