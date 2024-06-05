package com.faithsafe.api.authentication.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.servlet.view.RedirectView;

public interface AuthenticationService {

  void checkForRegister(RegisterRequest request);

  AuthenticationResponse authenticate(AuthenticationRequest request);

  AuthenticationResponse refreshToken(HttpServletRequest request);

  RedirectView verifyEmail(String token);
}
