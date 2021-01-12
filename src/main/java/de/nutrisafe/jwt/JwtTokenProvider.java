package de.nutrisafe.jwt;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import io.jsonwebtoken.*;
import org.bouncycastle.util.encoders.UTF8;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.*;

import static de.nutrisafe.UserDatabaseConfig.*;

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
    @Autowired
    private UserDetailsManager userDetailsManager;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    private String oauthUsername = null;
    private boolean externalUser = false;
    private String exp;
    HashMap<String, String> externalUsers = new HashMap<>();

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
    public UserDetails createOAuthUser(String name){
        UserDetailsManager userDetailsManager = this.userDetailsManager;
        if(!userDetailsManager.userExists(name)) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(ROLE_USER));
            UserDetails user = new org.springframework.security.core.userdetails.User(name,
                    "", authorities);
            return user;
        }
        return null;
    }

    public Authentication getAuthentication(String token) {
        if(externalUser){
            externalUser = false;
            UserDetails user = createOAuthUser(oauthUsername);
            int exists = 0;
            try {
                exists = jdbcTemplate.queryForObject("SELECT 1 FROM external_user_to_whitelist WHERE username = ? LIMIT 1", new Object[]{oauthUsername}, Integer.class);
                System.out.println(exists);
            }catch(EmptyResultDataAccessException | NullPointerException ignored){}
            if(exists == 0) {
                jdbcTemplate.execute("insert into external_user_to_whitelist(username, whitelist) values ('" + oauthUsername + "', '" + DEFAULT_READ_WHITELIST + "')");
                removeExternalUser(oauthUsername);
            }
            return new UsernamePasswordAuthenticationToken(user, "", user.getAuthorities());
        }
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public void removeExternalUser(String name){
        Thread t = new Thread(() ->{
            long now = System.currentTimeMillis();
            long ttl = (Integer.parseInt(externalUsers.get(name))*1000L) - now;
            System.out.println("ttl: " + ttl/1000L);
            try {
                Thread.sleep(ttl);
                jdbcTemplate.execute("delete from external_user_to_whitelist where username=" + "'" + name + "'");
                externalUsers.remove(name);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });
        t.start();
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
                try{
                    if(checkOauthToken(token))
                        return true;
                }catch(Exception e2){
                    try{
                        System.err.println("Check Google Token");
                        if(checkGoogleOauthToken(token))
                            return true;
                    }catch (Exception e3) {
                        System.err.println("[NutriSafe REST API] Authorization Server Error");
                    }
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
        HashMap response = webClient.post().uri("http://localhost:8085/oauth/check_token")
                .accept(MediaType.ALL).contentType(MediaType.APPLICATION_FORM_URLENCODED).body(BodyInserters.fromFormData(body))
                .exchange()
                .block()
                .bodyToMono(HashMap.class)
                .block();
        System.out.println(response);
        if(response.containsKey("user_name")) {
            oauthUsername = response.get("user_name").toString();
            System.out.println("OAUTHUSERNAME-----------------> " + oauthUsername);
            return true;
        }
        return false;
    }

    public boolean checkGoogleOauthToken(String token){
        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", token);
        WebClient webClient = WebClient.builder()
                //.defaultHeaders(header -> header.setBasicAuth("client1", "12345678"))
                .build();
        HashMap response;
        try{
            response = webClient.post().uri("https://oauth2.googleapis.com/tokeninfo?id_token=" + token)
                    .accept(MediaType.ALL).contentType(MediaType.APPLICATION_FORM_URLENCODED).body(BodyInserters.fromFormData(body))
                    .exchange()
                    .block()
                    .bodyToMono(HashMap.class)
                    .block();
        }catch(NullPointerException e){
            e.getMessage();
            return false;
        }
        if(response != null && response.containsKey("given_name")){
            externalUser = true;
            oauthUsername = response.get("given_name").toString(); //TODO: set name differently
            exp = response.get("exp").toString();
            externalUsers.put(oauthUsername, exp);
            System.err.println(response);
            return true;
        }
        return false;
    }
}