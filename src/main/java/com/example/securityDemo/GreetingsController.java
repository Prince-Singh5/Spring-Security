package com.example.securityDemo;


import com.example.securityDemo.jwt.JwtUtils;
import com.example.securityDemo.jwt.LoginRequest;
import com.example.securityDemo.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

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

    //below method will take the user name and password do the validation and provide the token
    //you can also check the char 1,2,3 is done using this.

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        try{

            //it creates the token and authenticate the users.
            authentication = authenticationManager.
                    authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
        }catch (AuthenticationException e){
            final Map<String,Object> body = new HashMap<>();
            body.put("message","Bad credential");
            body.put("status",false);
            return new ResponseEntity<>(body, HttpStatus.NOT_FOUND);
        }

        //flow is first we authenticate and after that we set the context for the session and after that
        //we create the token

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUserName(userDetails);

        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());

        LoginResponse response = new LoginResponse(jwtToken,userDetails.getUsername(),roles);

        return ResponseEntity.ok(response);
    }

}
