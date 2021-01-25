package de.nutrisafe.jwt;

import io.jsonwebtoken.*;
import org.bouncycastle.util.encoders.UTF8;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

@Lazy
@Component
@DependsOn("userDetailsService")
@ComponentScan(basePackages = {"de.nutrisafe"})
public class JwtTokenProvider {

    @Value("${security.jwt.token.secret-key:secret}")
    private String secretKey = "secret";
    @Value("${security.jwt.token.expire-length:3600000}")
    private long validityInMilliseconds = 3600000; // 1h
    @Autowired
    private UserDetailsService userDetailsService;
    private String oauthUsername = null;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(String username, List<String> authorities) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("authorities", authorities);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        return Jwts.builder()//
                .setClaims(claims)//
                .setIssuedAt(now)//
                .setExpiration(validity)//
                .signWith(SignatureAlgorithm.HS256, secretKey)//
                .compact();
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        if(token.length() > 250)
            return oauthUsername;
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            try {
                if (checkOauthToken(token))
                    return true;
            } catch (Exception e2) {
                System.err.println("[NutriSafe REST API] Authorization Server Error");
            }
            System.err.println("[NutriSafe REST API] Invalid JWT token");
            return false;
        }
    }


    public boolean checkOauthToken(String token){
        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", token);
        WebClient webClient = WebClient.builder()
                .defaultHeaders(header -> header.setBasicAuth("client1", "12345678"))
                .build();
        HashMap response;
        try{
            response = webClient.post().uri("http://localhost:8085/oauth/check_token")
                    .accept(MediaType.ALL).contentType(MediaType.APPLICATION_FORM_URLENCODED).body(BodyInserters.fromFormData(body))
                    .exchange()
                    .block()
                    .bodyToMono(HashMap.class)
                    .block();
        }catch(NullPointerException e){
            return false;
        }
        if(response != null && response.containsKey("user_name")) {
            oauthUsername = response.get("user_name").toString();
            return true;
        }
        return false;
    }

}