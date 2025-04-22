# Spring Security && JWT

### Implementing JWT Authentication
```
1. JwtUtils
2. AuthTokenFilter
3. AuthEntryPointJwt
4. SecurityConfig
```
#### JwtUtils
Contains utility methods for generating, validating and extracting username from a JWT.
```
public String getJwtFromHeader(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");

    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
        return bearerToken.substring(7);
    }
    return null;
}

public String generateTokenFromUsername(UserDetails userDetails) {
    String username = userDetails.getUsername();
    return Jwts.builder()
            .subject(username)
            .issuedAt(new Date())
            .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
            .signWith(key())
            .compact();
}

public String getUserNameFromJwtToken(String token) {
    return Jwts.parser().verifyWith((SecretKey) key()).build()
            .parseSignedClaims(token)
            .getPayload().getSubject();
}

public boolean validateJwtToken(String authToken) {
    try {
        Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
        return true;
    } catch (MalformedJwtException | IllegalArgumentException | ExpiredJwtException | UnsupportedJwtException e) {
        System.err.println(e.getMessage());
    }
    return false;
}

public Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
}
```
- Tokens are senting using HTTP Authorization header
  - Format -> Authorization: Bearer `<token>`
  
### Validate JWT
![](https://user-images.githubusercontent.com/49062985/82150987-12bac300-9895-11ea-8430-a89e4d20a72d.jpg)

![](https://user-images.githubusercontent.com/49062985/82150976-0b93b500-9895-11ea-9ee8-ae2ea3196e8b.jpg)

![](https://user-images.githubusercontent.com/49062985/82150947-de470700-9894-11ea-8ae1-473762d61e80.jpg)

![](https://user-images.githubusercontent.com/49062985/81495542-e8449500-92eb-11ea-9cc5-316568379779.png)

<img width="994" alt="Image" src="https://github.com/user-attachments/assets/b3f88f82-678d-4ca5-a915-cd504a4de1f0" />

<img width="994" alt="Image" src="https://github.com/user-attachments/assets/00ffb613-903f-41a1-8e18-55420fc6351d" />

<img width="994" alt="Image" src="https://github.com/user-attachments/assets/c6424a47-3c42-4488-a858-f8bf0fb87f73" />
