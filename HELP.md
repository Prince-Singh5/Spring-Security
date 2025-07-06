
#JWT Authentication Overview

This project implements JWT (JSON Web Token) based authentication for secure access to protected APIs. Users must log in to receive a JWT, which is then included in request headers for authorization.

🔑 Authentication Flow
Login Endpoint

POST /signin

Accepts credentials as JSON (e.g. username and password)

Returns a JWT in the response

Token Usage

Include the JWT in the Authorization header for protected endpoints:

Authorization: Bearer <your_token>

Protected Routes

Secured using Spring Security configuration

Requests without valid tokens receive a 401 Unauthorized

Key Components

Component	           Description
AuthEntryPointJwt	   Handles unauthorized access attempts
AuthTokenFilter	     Filters incoming requests and validates JWTs
JwtUtils	           Utility class for generating and verifying tokens
LoginRequest	       DTO for receiving login credentials
LoginResponse	       DTO for returning JWT and additional user info
SecurityConfig	     Configures authentication, authorization, and role access

