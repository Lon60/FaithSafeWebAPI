package com.faithsafe.api.authentication.auth;

import com.faithsafe.api.authentication.TokenGenerator;
import com.faithsafe.api.email.EmailService;
import com.faithsafe.api.authentication.JwtService;
import com.faithsafe.api.authentication.Role;
import com.faithsafe.api.authentication.User;
import com.faithsafe.api.authentication.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.regex.Pattern;
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
import org.springframework.web.servlet.view.RedirectView;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

  private static final String EMAIL_PATTERN =
      "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";
  private static final Pattern emailPattern = Pattern.compile(EMAIL_PATTERN);
  private final EmailService emailService;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public void checkForRegister(RegisterRequest request) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    SimpleGrantedAuthority adminRole = new SimpleGrantedAuthority(Role.ADMIN.name());

    if (Objects.equals(request.getRole(), "ADMIN")) {
      if (!authentication.getAuthorities().contains(adminRole)) {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN,
            "Only admins can create admin accounts");
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

    if (!emailPattern.matcher(request.getEmail()).matches()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not valid");
    }
    register(request);
  }

  public RedirectView verifyEmail(String token) {
    try {
      User user = userRepository.findByEmailVerificationToken(token).orElseThrow();
      if (user.isEmailVerified()) {
        return new RedirectView("https://faithsafe.net/login?emailverified=false");
      }
      if (Objects.equals(user.getEmailVerificationToken(), token)) {
        user.setEmailVerified(true);
        userRepository.save(user);
        return new RedirectView("https://faithsafe.net/login?emailverified=true");
      } else {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid verification token");
      }
    } catch (NoSuchElementException e) {
      return new RedirectView("https://faithsafe.net/login?emailverified=false");
    }
  }

  private void register(RegisterRequest request) {
    Role assignedRole = Objects.equals(request.getRole(), "ADMIN") ? Role.ADMIN : Role.USER;
    User user = User.builder().username(request.getUsername()).email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword())).role(assignedRole).build();

    sendVerificationEmail(user);
  }

  public void sendVerificationEmail(User user) {
    user.setEmailVerificationToken(TokenGenerator.generateToken(user.getUsername()));
    emailService.sendSimpleEmail(user.getEmail(), "Verify Your FaithSafe Account",
        "Open the following Url: " + "api.faithsafe.net/auth/verify?token="
            + user.getEmailVerificationToken());
    user.setEmailVerified(false);
    userRepository.save(user);
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
    if (!user.isEmailVerified()) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Email is not verified");
    }
    Map<String, Object> extraClaims = new HashMap<>();
    extraClaims.put("role", "ROLE_" + user.getRole().toString());

    String jwtToken = jwtService.generateToken(extraClaims, user);
    String refreshToken = jwtService.generateRefreshToken(user);
    return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken)
        .build();
  }
}
