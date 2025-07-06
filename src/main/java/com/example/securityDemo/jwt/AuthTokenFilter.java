package com.example.securityDemo.jwt;



//This class will intercept the request and validate the token

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


// by using this we are adding our own custom filter

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    //OncePerRequestFilter class insures that this class is executed only once per http request.

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.debug("AuthTokenFilter called from  URI : {}",request.getRequestURI());
        try{
                String jwt = parseJwt(request);
                if(jwt != null && jwtUtils.validateJwtToken(jwt)){
                    String username = jwtUtils.getUserNameFromJwtToken(jwt);
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);  //getting the userDetails of the users.

                    //below line create the authentication object
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                    logger.debug("Roles from the jwt : {}",userDetails.getAuthorities());

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    //we are setting the security context
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
        }catch(Exception e){
            logger.error("Can't set user authentication : {}",e);
        }
        filterChain.doFilter(request,response);
    }

    private  String parseJwt(HttpServletRequest request){
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("Authentication filter jwt : {}",jwt);
        return jwt;
    }

}
