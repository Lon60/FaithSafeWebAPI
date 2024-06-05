package com.faithsafe.api.authentication.user;

import com.faithsafe.api.authentication.Role;
import com.faithsafe.api.authentication.User;
import com.faithsafe.api.authentication.UserRepository;
import com.faithsafe.api.authentication.auth.AuthenticationServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class UserService {

  private final UserRepository userRepository;
  private final AuthenticationServiceImpl authenticationService;

  public User readUserOwn() {
    String username = SecurityContextHolder.getContext().getAuthentication().getName();
    return userRepository.findByUsername(username).orElseThrow();
  }

  public void updateUserOwn(UserDto.WithPassword userDto) {
    User user = readUserOwn();
    if (userDto.getUsername() != null) user.setUsername(userDto.getUsername());
    if (userDto.getEmail() != null && !user.getEmail().equals(userDto.getEmail())) {
      user.setEmail(userDto.getEmail());
      authenticationService.sendVerificationEmail(user);
    }
    if (userDto.getPassword() != null) user.setPassword(userDto.getPassword());
    userRepository.save(user);
  }

  public UserDto getUser() {
    User user = readUserOwn();
    return UserDto.builder()
        .username(user.getUsername())
        .email(user.getEmail())
        .role(user.getRole())
        .build();
  }

  public void deleteUser() {
    User user = readUserOwn();
    if (user.getRole() == Role.ADMIN) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admins cannot delete their own account");
    }
    userRepository.delete(user);
  }
}
