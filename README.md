# Spring Security && JWT

### Implementing JWT Authentication
```
1. JwtUtils
2. AuthTokenFilter
3. AuthEntryPointJwt
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
- Tokens are sent using HTTP Authorization header
  - Format -> Authorization: Bearer `<token>`

### AuthTokenFilter
Intercepts all incoming requests to check for a valid JWT extracted from the header and setting the autehntication context if the token is valid.
```
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
    try {
        String jwt = parseJwt(request);

        if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
            String username = jwtUtils.getUserNameFromJwtToken(jwt);

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    } catch (Exception e) {
        System.err.println(e.getMessage());
    }
    filterChain.doFilter(request, response);
}
```
### AuthEntryPointJwt
Provides custom handling for unauthroized requests.
```
@Override
public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    final Map<String, Object> body = new HashMap<>();
    body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
    body.put("error", "Unauthorized");
    body.put("message", authException.getMessage());
    body.put("path", request.getServletPath());

    final ObjectMapper mapper = new ObjectMapper();
    mapper.writeValue(response.getOutputStream(), body);
}
```

## Generate JWT
Accepts username (ID) and password and return JWT as response
<img width="550" alt="Image" src="https://github.com/user-attachments/assets/00ffb613-903f-41a1-8e18-55420fc6351d" />

![](https://user-images.githubusercontent.com/49062985/82150947-de470700-9894-11ea-8ae1-473762d61e80.jpg)
![](https://user-images.githubusercontent.com/49062985/82150976-0b93b500-9895-11ea-9ee8-ae2ea3196e8b.jpg)
- UserDetailsService retrieves userdetails such as username, password, authorities, and other attributes from DB
    - provide the userdetails to AuthenticaionManger.
      
## Validate JWT
![](https://user-images.githubusercontent.com/49062985/82150987-12bac300-9895-11ea-8430-a89e4d20a72d.jpg)
- For every request to the server, AuthTokenFilter is provoked and validate the JWT.
<img width="550" alt="Image" src="https://github.com/user-attachments/assets/c6424a47-3c42-4488-a858-f8bf0fb87f73" />
