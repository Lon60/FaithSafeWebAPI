package com.faithsafe.api.authentication.user;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Tag(name = "User")
public class UserController {

  private final UserService userService;

  @PutMapping("/user")
  public void updateUser(@RequestBody UserDto.WithPassword userDto) {
    userService.updateUserOwn(userDto);
  }

  @GetMapping("/user")
  public UserDto getUser() {
    return userService.getUser();
  }

  @DeleteMapping("/user")
  public void deleteUser() {
    userService.deleteUser();
  }
}
