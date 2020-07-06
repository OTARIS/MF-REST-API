package de.nutrisafe;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import de.nutrisafe.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.ResponseEntity.*;

@Lazy
@RestController
@DependsOn("jwtTokenProvider")
public class NutriSafeRestController {

    private final Utils helper = new Utils();
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JwtTokenProvider jwtTokenProvider;
    @Autowired
    PersistenceManager persistenceManager;

    @GetMapping(value = "/get", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> get(@RequestParam String contract, @RequestParam(required = false) String[] query) {
        try {
            User user = persistenceManager.getCurrentUser();
            if(user == null)
                throw new UsernameNotFoundException("Username not found");
            else {
                Map<Object, Object> model = new HashMap<>();
                model.put("response", helper.evaluateTransaction(contract, query));
                return ok(model);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping(value = "/submit", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> submit(@RequestParam String contract, @RequestBody String[] order) {
        try {
            User user = persistenceManager.getCurrentUser();
            if(user == null)
                throw new UsernameNotFoundException("Username not found");
            else {
                Map<Object, Object> model = new HashMap<>();
                model.put("response", helper.submitTransaction(contract, order));
                return ok(model);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> auth(@RequestBody String body) {
        String username;
        String password;
        try {
            JsonObject jsonObject = JsonParser.parseString(body).getAsJsonObject();
            username = jsonObject.get("username").getAsString();
            password = jsonObject.get("password").getAsString();
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return ResponseEntity.badRequest().build();
        }
        try {
            PersistenceManager userDb = persistenceManager;
            if(userDb.userExists(username)) {
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
                String token = jwtTokenProvider.createToken(username, userDb.getAuthorities(username));
                Map<Object, Object> model = new HashMap<>();
                model.put("username", username);
                model.put("token", token);
                return ok(model);
            } else throw new UsernameNotFoundException("Username " + username + " not found");
        } catch (AuthenticationException e) {
            System.err.println(e.getMessage() + " - Invalid username/password supplied.");
            throw new BadCredentialsException("Invalid username/password supplied");
        }
    }

}
