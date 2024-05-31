package com.faithsafe.api.authentication.auth;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthenticationService {

  AuthenticationResponse checkForRegister(RegisterRequest request);

  AuthenticationResponse authenticate(AuthenticationRequest request);

  AuthenticationResponse refreshToken(HttpServletRequest request);
}
