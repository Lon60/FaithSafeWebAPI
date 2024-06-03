package com.faithsafe.api.authentication.auth;

import com.faithsafe.api.email.EmailService;
import java.util.Random;
import com.faithsafe.api.authentication.JwtService;
import com.faithsafe.api.authentication.Role;
import com.faithsafe.api.authentication.User;
import com.faithsafe.api.authentication.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService{

  private final EmailService emailService;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse checkForRegister(RegisterRequest request) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    SimpleGrantedAuthority adminRole = new SimpleGrantedAuthority(Role.ADMIN.name());

    if (Objects.equals(request.getRole(), "ADMIN")) {
      if (!authentication.getAuthorities().contains(adminRole)) {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Only admins can create admin accounts");
      }
    }

    if (request.getUsername() == null || request.getUsername().isEmpty()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is required");
    }
    if (request.getPassword() == null || request.getPassword().isEmpty()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
    }
    if (request.getEmail() == null || request.getEmail().isEmpty()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
    }
    if (userRepository.findByUsername(request.getUsername()).isPresent()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already exists");
    }
    return register(request);
  }

  public void verifyEmail(int code) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    if (user.isEmailVerified()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already verified");
    }
    if (user.getEmailVerificationCode() == code) {
      user.setEmailVerified(true);
      userRepository.save(user);
    } else {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid verification code");
    }
  }

  private AuthenticationResponse register(RegisterRequest request) {
    Random random = new Random();

    Role assignedRole = Objects.equals(request.getRole(), "ADMIN") ? Role.ADMIN : Role.USER;
    User user = User.builder().username(request.getUsername()).email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword())).role(assignedRole).build();

    user.setEmailVerified(false);
    user.setEmailVerificationCode(random.nextInt((999999 - 100000) + 1) + 100000);
    userRepository.save(user);

    emailService.sendSimpleEmail(user.getEmail(), "Verify Your FaithSafe Account", "Your Code: " + user.getEmailVerificationCode());

    return getAuthenticationResponse(user);
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

    User user = userRepository.findByUsername(request.getUsername())
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    return getAuthenticationResponse(user);
  }

  public AuthenticationResponse refreshToken(HttpServletRequest request) {
    String refreshToken = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (refreshToken == null || !refreshToken.startsWith("Bearer ")) {
      throw new AuthorizationDeniedException("Invalid authorization token format", () -> false);
    }
    refreshToken = refreshToken.substring(7);
    String username = jwtService.extractUsername(refreshToken);

    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));

    if (!jwtService.isTokenValid(refreshToken, user)) {
      throw new AuthorizationDeniedException("Invalid refresh token", () -> false);
    }

    return getAuthenticationResponse(user);
  }

  private AuthenticationResponse getAuthenticationResponse(User user) {
    Map<String, Object> extraClaims = new HashMap<>();
    extraClaims.put("role", "ROLE_" + user.getRole().toString());

    String jwtToken = jwtService.generateToken(extraClaims, user);
    String refreshToken = jwtService.generateRefreshToken(user);
    return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken)
        .build();
  }
}
