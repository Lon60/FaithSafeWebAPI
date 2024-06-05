package com.faithsafe.api.authentication.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequiredArgsConstructor
@Tag(name = "Auth")
public class AuthenticationController {

  private final AuthenticationService authenticationService;

  @Operation(description = """
      # Info
      Registers a user.\s
      ## Security
      This endpoint does not require a role unless an **ADMIN** user is created.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
  @PostMapping("/auth/register")
  @ResponseStatus(HttpStatus.CREATED)
  public void register(@RequestBody RegisterRequest request) {
    authenticationService.checkForRegister(request);
  }

  @Operation(description = """
      # Info
      Authenticates a user and returns the JWT.\s
      ## Security
      This end point does **not require a role**.
      """)
  @PermitAll
  @PostMapping("/auth")
  public HttpHeaders authenticate(@RequestBody AuthenticationRequest request) {
    String jwtToken = authenticationService.authenticate(request).getAccessToken();
    String refreshToken = authenticationService.authenticate(request).getRefreshToken();
    HttpHeaders headers = new HttpHeaders();
    headers.add("Authorization", "Bearer " + jwtToken);
    headers.add("Refresh-Token", "Bearer " + refreshToken);
    return headers;
  }

  @Operation(description = """
      # Info
      Uses RefreshToken to generate new JWT and RefreshToken.\s
      ## Security
      This end point needs the **Refresh** token as the JWT.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
  @PermitAll
  @PostMapping("/auth/refresh")
  public HttpHeaders refreshToken(HttpServletRequest request) {
    AuthenticationResponse authResponse = authenticationService.refreshToken(request);

    HttpHeaders headers = new HttpHeaders();
    headers.add("Authorization", "Bearer " + authResponse.getAccessToken());
    headers.add("Authorization", "Refresh " + authResponse.getRefreshToken());
    return headers;
  }

  @Operation(description = """
      # Info
      Verify email adress.\s
      ## Security
      This end point does **not require a role**.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
  @GetMapping("/auth/verify")
  public RedirectView verifyEmail(
      @RequestParam String token
  ) {
    return authenticationService.verifyEmail(token);
  }
}
