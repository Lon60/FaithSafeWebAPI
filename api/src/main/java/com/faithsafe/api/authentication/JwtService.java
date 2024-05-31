package com.faithsafe.api.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

  @Value("${JWT_SECRET_KEY}")
  private String jwtSecretKey;
  @Value("${JWT_EXPIRATION}")
  private int jwtExpiration;
  @Value("${REFRESH_EXPIRATION}")
  private int refreshExpiration;

  public String extractUsername(String jwtToken) {
    return extractClaim(jwtToken, Claims::getSubject);
  }

  public String extractRole(String jwtToken) {
    return extractClaim(jwtToken, claims -> claims.get("role", String.class));
  }

  public <T> T extractClaim(
      String jwtToken, Function<Claims, T> claimsResolver
  ) {
    final Claims claims = extractAllClaims(jwtToken);
    return claimsResolver.apply(claims);
  }

  public String generateToken(
      Map<String, Object> extraClaims, UserDetails userDetails
  ) {


    return buildToken(extraClaims, userDetails, jwtExpiration);
  }

  public String generateRefreshToken(
      UserDetails userDetails
  ) {


    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
  }

  private String buildToken(
      Map<String, Object> extraClaims, UserDetails userDetails, int expiration
  ) {
    return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();
  }

  public boolean isTokenValid(
      String jwtToken, UserDetails userDetails
  ) {
    final String username = extractUsername(jwtToken);
    return username.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken);
  }

  private boolean isTokenExpired(String jwtToken) {
    return extractExpiration(jwtToken).before(new Date());
  }

  private Date extractExpiration(String jwtToken) {
    return extractClaim(jwtToken, Claims::getExpiration);
  }

  private Claims extractAllClaims(String jwtToken) {
    return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(jwtToken)
        .getBody();
  }

  private Key getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(jwtSecretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }


}
