package com.faithsafe.api.authentication.user;

import com.faithsafe.api.authentication.Role;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
public class UserDto {
  private String username;
  private String email;
  private Role role;


  @Setter
  @Getter
  @SuperBuilder
  @NoArgsConstructor
  public static class WithPassword extends UserDto {
    protected String password;
  }
}
