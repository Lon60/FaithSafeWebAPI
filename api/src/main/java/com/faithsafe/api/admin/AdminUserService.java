package com.faithsafe.api.admin;

import com.faithsafe.api.authentication.User;
import com.faithsafe.api.authentication.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminUserService {

    private final UserRepository userRepository;

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow();
    }

    public List<User> getAllUser() {
        return userRepository.findAll();
    }

    public void updateUserByUsername(String username, User newUser) {
        User user = userRepository.findByUsername(username).orElseThrow();

        user.setUsername(newUser.getUsername());
        user.setPassword(newUser.getPassword());
        user.setRole(newUser.getRole());
        user.setEmailVerified(newUser.isEmailVerified());
        userRepository.save(user);
    }
}
