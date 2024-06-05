package com.faithsafe.api.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

public class TokenGenerator {

  public static String generateToken(String username) {
    String randomUUID = UUID.randomUUID().toString();
    String token = username + ":" + randomUUID;
    return hashToken(token);
  }

  private static String hashToken(String token) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Error generating token hash", e);
    }
  }
}
