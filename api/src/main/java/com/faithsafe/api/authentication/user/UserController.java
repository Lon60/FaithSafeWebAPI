package com.faithsafe.api.authentication.user;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
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
}
