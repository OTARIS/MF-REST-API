package de.nutrisafe;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import de.nutrisafe.jwt.JwtTokenProvider;
import org.apache.commons.io.FileUtils;
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
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.ResponseEntity.*;

@Lazy
@RestController
@DependsOn("jwtTokenProvider")
public class NutriSafeRestController {



    private final Utils helper = new Utils();
    @Autowired
    private Config config;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JwtTokenProvider jwtTokenProvider;
    @Autowired
    PersistenceManager persistenceManager;

    @GetMapping(value = "/get", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> get(@RequestParam String function, @RequestParam(required = false) String[] args) {

        try {
            User user = persistenceManager.getCurrentUser();
            if(user == null)
                throw new UsernameNotFoundException("Username not found");
            else {
                String response = helper.evaluateTransaction(function, args);
                JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();
                if (responseJson.get("status").toString().equals("\"200\"")){
                    return ok(responseJson.get("response").toString());
                }
                else {
                    return badRequest().body(responseJson.get("response").toString());
                }
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping(value = "/select", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> select(@RequestBody String body) {
        try {
            JsonObject bodyJson = JsonParser.parseString(body).getAsJsonObject();
            String[] args = {bodyJson.toString()};
            String response = helper.evaluateTransaction("queryChaincodeByQueryString", args);
            JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();
            return ok(responseJson.get("response").toString());
        }
        catch (Exception e){
                System.err.println(e.getMessage());
                return ResponseEntity.badRequest().build();
            }
    }

    @PostMapping(value = "/submit", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> submit(@RequestParam String function, @RequestBody(required = false) String body) {
        try {
            User user = persistenceManager.getCurrentUser();
            if(user == null)
                throw new UsernameNotFoundException("Username not found");
            else {
                JsonObject bodyJson = JsonParser.parseString(body).getAsJsonObject();
                File jsonFile = ResourceUtils.getFile("classpath:key_defs.json");
                JsonObject keyDefsJson = (JsonObject) JsonParser.parseString( FileUtils.readFileToString(jsonFile, StandardCharsets.UTF_8));

                HashMap<String, String> keyDefs  = new Gson().fromJson(keyDefsJson, new TypeToken<HashMap<String, String>>() {}.getType());
                ArrayList<String> attributesToPass = new ArrayList<>();
                //iterate over the allowed key definitions. If the request body contains this key, the value will be added to attributesToPass
                for (Map.Entry<String, String> entry : keyDefs.entrySet()) {
                    if (bodyJson.has(entry.getValue())){
                        attributesToPass.add(bodyJson.get(entry.getValue()).toString().replace("\"",""));
                    }
                }
                //private attributes
                HashMap<String, byte[]> pArgsByteMap = new HashMap<>();
                if (bodyJson.has("pArgs")){
                    String pArgs = bodyJson.getAsJsonObject("pArgs").toString();
                    HashMap<String, String> pArgsMap = new Gson().fromJson(pArgs, new TypeToken<HashMap<String, String>>() {}.getType());
                    for (Map.Entry<String, String> entry : pArgsMap.entrySet()) {
                        pArgsByteMap.put(entry.getKey(), entry.getValue().getBytes());
                    }
                }
                String response = helper.submitTransaction(config, function, attributesToPass.toArray(new String[attributesToPass.size()]), pArgsByteMap);
                JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();

                if (responseJson.get("status").toString().equals("\"200\"")){
                    return ok(responseJson.get("response").toString());
                }
                else {
                    return badRequest().body(responseJson.get("response").toString());
                }
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
