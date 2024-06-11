package com.faithsafe.api.admin;

import com.faithsafe.api.authentication.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@Tag(name = "User (Admin)")
public class AdminUserController {

    private final AdminUserService adminUserService;

    @Operation(description = """
      # Info
      Gets a user by username.\s
      ## Security
      This endpoint does need **ADMIN**.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
    @GetMapping("/admin/user/{username}")
    public User getUserByUsername(@PathVariable String username) {
        return adminUserService.getUserByUsername(username);
    }

    @Operation(description = """
      # Info
      Gets all user in a list.\s
      ## Security
      This endpoint does need **ADMIN**.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
    @GetMapping("/admin/user")
    public List<User> getAllUser() {
        return adminUserService.getAllUser();
    }

    @Operation(description = """
      # Info
      Updates a user by username.\s
      ## Security
      This endpoint does need **ADMIN**.
      """, security = {@SecurityRequirement(name = "BearerAuth")})
    @PutMapping("/admin/user/{username}")
    public void updateUserByUsername(@PathVariable String username, @RequestBody User newUser) {
        adminUserService.updateUserByUsername(username, newUser);
    }
}
