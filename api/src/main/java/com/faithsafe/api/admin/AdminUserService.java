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
}
