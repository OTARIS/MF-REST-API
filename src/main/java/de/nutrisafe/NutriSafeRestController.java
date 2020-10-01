package de.nutrisafe;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import de.nutrisafe.jwt.JwtTokenProvider;
import org.apache.commons.compress.PasswordRequiredException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowCountCallbackHandler;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.*;

import javax.json.Json;
import javax.persistence.criteria.CriteriaBuilder;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

import static de.nutrisafe.UserDatabaseConfig.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.ResponseEntity.*;

@Lazy
@CrossOrigin()
@RestController
@DependsOn("jwtTokenProvider")
public class NutriSafeRestController {

    private Utils helper;

    // bruteforce protection attributes
    private final HashMap<String, Integer> triesCount = new HashMap<>();
    private final HashMap<String, Long> lastTry = new HashMap<>();

    @Autowired
    private Config config;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JwtTokenProvider jwtTokenProvider;
    @Autowired
    PersistenceManager persistenceManager;
    @Autowired
    UserDetailsManager userDetailsManager;

    @GetMapping(value = "/get", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> get(@RequestParam String function, @RequestParam(required = false) String[] args) {
        try {
            UserDetails user = persistenceManager.getCurrentUser();
            if(user == null)
                throw new UsernameNotFoundException("No valid session. Please authenticate again.");
            return switch(function) {
                case "getAllUsers" -> getAllUsers();
                case "getUserInfo" -> getUserInfo(user.getUsername());
                case "getUserInfoOfUser" -> getUserInfo(args);
                case "getWhitelists" -> getWhitelists();
                default -> hyperledgerGet(function, args);
            };
        } catch (RequiredException | InvalidException | UsernameNotFoundException e) {
            return badRequest().body(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return badRequest().build();
        }
    }

    @PostMapping(value = "/select", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> select(@RequestBody String body) {
        try {
            UserDetails user = persistenceManager.getCurrentUser();
            if(user == null)
                throw new UsernameNotFoundException("No valid session. Please authenticate again.");
            JsonObject bodyJson = JsonParser.parseString(body).getAsJsonObject();
            String[] args = {bodyJson.toString()};
            String response = getHelper().evaluateTransaction("queryChaincodeByQueryString", args);
            JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();
            return ok(responseJson.get("response").toString());
        } catch (UsernameNotFoundException e) {
            return badRequest().body(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return badRequest().build();
        }
    }

    @PostMapping(value = "/submit", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> submit(@RequestParam String function, @RequestBody(required = false) String body) {
        try {
            UserDetails user = persistenceManager.getCurrentUser();
            if(user == null)
                throw new UsernameNotFoundException("No valid session. Please authenticate again.");
            else {
                JsonObject bodyJson = JsonParser.parseString(body).getAsJsonObject();
                return switch (function) {
                    case "createUser" -> createUser(bodyJson);
                    case "deleteUser" -> deleteUser(bodyJson);
                    case "setRole" -> setRole(bodyJson);
                    case "createWhitelist" -> createWhitelist(bodyJson);
                    case "deleteWhitelist" -> deleteWhitelist(bodyJson);
                    case "linkFunctionToWhitelist" -> linkFunctionToWhitelist(bodyJson);
                    case "unlinkFunctionFromWhitelist" -> unlinkFunctionFromWhitelist(bodyJson);
                    case "linkUserToWhitelist" -> linkUserToWhitelist(bodyJson);
                    case "unlinkUserFromWhitelist" -> unlinkUserFromWhitelist(bodyJson);
                    default -> hyperledgerSubmit(function, bodyJson);
                };
            }
        } catch (RequiredException | InvalidException | UsernameNotFoundException e) {
            return badRequest().body(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return badRequest().build();
        }
    }

    @PostMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> auth(@RequestBody String body) {
        try {
            JsonObject jsonObject = JsonParser.parseString(body).getAsJsonObject();
            String username = retrieveUsername(jsonObject, true,true);
            String password = retrievePassword(jsonObject, true);
            // bruteforce protection
            if(lastTry.get(username) != null && lastTry.get(username) + 10000 < System.currentTimeMillis()
                    && triesCount.get(username) > 2)
                return badRequest().body("Suspicious behavior detected. Please wait 10 seconds before trying again.");
            try {
                PersistenceManager userDb = persistenceManager;
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
                String token = jwtTokenProvider.createToken(username, userDb.getAuthorities(username));
                Map<Object, Object> model = new HashMap<>();
                model.put("username", username);
                model.put("token", token);
                return ok(model);
            } catch (AuthenticationException e) {
                // bruteforce protection: count unsuccessful attempts if they happen in less than 10 seconds
                if (lastTry.get(username) + 10000 < System.currentTimeMillis())
                    triesCount.put(username, triesCount.get(username));
                else
                    triesCount.put(username, 0);
                lastTry.put(username, System.currentTimeMillis());
                return badRequest().body("Wrong password.");
            }
        } catch(RequiredException | InvalidException e) {
            return badRequest().body(e.getMessage());
        } catch(Exception e) {
            e.printStackTrace();
            return badRequest().build();
        }
    }

    private Utils getHelper() {
        if(helper == null) {
            config.setCompany(Main.mspId);
            config.setNetworkConfigPath(Main.connectionJson);
            config.setPrivateKeyPath(Main.privateKey);
            config.setCertPath(Main.adminCert);
            helper = new Utils(config);
        }
        return helper;
    }

    private ResponseEntity<?> hyperledgerGet(String function, String[] args) throws Exception {
        String response = getHelper().evaluateTransaction(function, args);
        JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();
        if (responseJson.get("status").toString().equals("\"200\""))
            return ok(responseJson.get("response").toString());
        else
            return badRequest().body(responseJson.get("response").toString());
    }

    private ResponseEntity<?> hyperledgerSubmit(String function, JsonObject bodyJson) {
        try {
            ClassPathResource classPathResource = new ClassPathResource("key_defs.json");
            InputStream inputStream = classPathResource.getInputStream();
            JsonObject keyDefsJson = (JsonObject) JsonParser.parseString(IOUtils.toString(inputStream, UTF_8));

            HashMap<String, String> keyDefs  = new Gson().fromJson(keyDefsJson, new TypeToken<HashMap<String, String>>() {}.getType());
            ArrayList<String> attributesToPass = new ArrayList<>();
            //iterates over the allowed key definitions. If the request body contains this key, the value will be added to attributesToPass
            for (int i = 1; i < keyDefs.size(); i++){
                if (bodyJson.has(keyDefs.get(String.valueOf(i)))){
                    attributesToPass.add(bodyJson.get(keyDefs.get(String.valueOf(i))).toString().replace("\"",""));
                }
            }
            //private attributes
            HashMap<String, byte[]> pArgsByteMap = new HashMap<>();
            if (bodyJson.has("pArgs")) {
                String pArgs = bodyJson.getAsJsonObject("pArgs").toString();
                HashMap<String, String> pArgsMap = new Gson().fromJson(pArgs, new TypeToken<HashMap<String, String>>() {}.getType());
                for (Map.Entry<String, String> entry : pArgsMap.entrySet()) {
                    pArgsByteMap.put(entry.getKey(), entry.getValue().getBytes());
                }
            }
            String response = getHelper().submitTransaction(function, attributesToPass.toArray(new String[attributesToPass.size()]), pArgsByteMap);
            JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();

            if (responseJson.get("status").toString().equals("\"200\"")){
                return ok(responseJson.get("response").toString());
            }
            else {
                return badRequest().body(responseJson.get("response").toString());
            }
        } catch (FileNotFoundException e) {
            return badRequest().body("REST API was unable to load the key defs for possible functions. " +
                    "Please contact the administrator.");
        } catch (IOException e) {
            return badRequest().body("REST API was unable to parse the key defs file for possible functions. " +
                    "Please contact the administrator.");
        }
    }

    private ResponseEntity<?> getAllUsers() {
        JsonObject response = new JsonObject();
        JsonArray usernames = new JsonArray();
        for(String username : persistenceManager.selectAllUsers())
            usernames.add(username);
        response.add("usernames", usernames);
        return ok(response.toString());
    }

    private ResponseEntity<?> getUserInfo(String[] args) throws RequiredException {
        if (args.length < 1)
            throw new RequiredException("Username required.");
        else
            return getUserInfo(args[0]);
    }

    private ResponseEntity<?> getWhitelists() {
        JsonObject response = new JsonObject();
        for(String whitelist : persistenceManager.selectAllWhitelists()) {
            JsonArray functions = new JsonArray();
            for(String function : persistenceManager.selectFunctionToWhitelistEntriesOfWhitelist(whitelist))
                functions.add(function);
            response.add(whitelist, functions);
        }
        return ok(response.toString());
    }

    private ResponseEntity<?> getUserInfo(String username) {
        JsonObject response = new JsonObject();
        response.addProperty("username", username);
        response.addProperty("role", getRole(username));
        JsonArray linkedToWhitelists = new JsonArray();
        Set<String> allowedFunctionSet = new HashSet<>();
        for(String whitelist : persistenceManager.selectUserToWhitelistEntriesOfUser(username)) {
            linkedToWhitelists.add(whitelist);
            allowedFunctionSet.addAll(persistenceManager.selectFunctionToWhitelistEntriesOfWhitelist(whitelist));
        }
        response.add("linkedToWhitelists", linkedToWhitelists);
        JsonArray allowedFunctions = new JsonArray();
        for(String function : allowedFunctionSet)
            allowedFunctions.add(function);
        response.add("allowedFunctions", allowedFunctions);
        return ok(response.toString());
    }

    private ResponseEntity<?> unlinkFunctionFromWhitelist(JsonObject bodyJson) throws InvalidException {
        String function = retrieveFunction(bodyJson, true);
        String whitelist = retrieveWhitelist(bodyJson, true, true);
        if(!persistenceManager.functionToWhitelistEntryExists(function, whitelist))
            throw new InvalidException(function + " is already unlinked from " + whitelist);
        persistenceManager.deleteFunctionToWhitelistEntry(function, whitelist);
        return ok(function + " unlinked from " + whitelist);
    }

    private ResponseEntity<?> linkFunctionToWhitelist(JsonObject bodyJson) throws InvalidException {
        String whitelist = retrieveWhitelist(bodyJson, true, true);
        String function = retrieveFunction(bodyJson, true);
        if(persistenceManager.functionToWhitelistEntryExists(function, whitelist))
            throw new InvalidException(function + " is already linked to " + whitelist + ".");
        persistenceManager.insertFunctionToWhitelistEntry(function, whitelist);
        return ok(function + " linked to " + whitelist);
    }

    private ResponseEntity<?> deleteWhitelist(JsonObject bodyJson) throws InvalidException {
        String whitelist = retrieveWhitelist(bodyJson, true, true);
        persistenceManager.deleteUserToWhitelistEntriesOfWhitelist(whitelist);
        persistenceManager.deleteFunctionToWhitelistEntriesOfWhitelist(whitelist);
        persistenceManager.deleteWhitelistEntry(whitelist);
        return ok(whitelist + " deleted.");
    }

    private ResponseEntity<?> createWhitelist(JsonObject bodyJson) throws InvalidException {
        String whitelist = retrieveWhitelist(bodyJson, true, false);
        if(persistenceManager.whitelistExists(whitelist))
            throw new InvalidException(whitelist + " already exists.");
        persistenceManager.insertWhitelist(whitelist);
        return ok(whitelist + " created.");
    }

    private ResponseEntity<?> linkUserToWhitelist(JsonObject bodyJson) throws InvalidException {
        String username = retrieveUsername(bodyJson, true, true);
        String whitelist = retrieveWhitelist(bodyJson, true, true);
        if(persistenceManager.userToWhitelistExists(username, whitelist))
            throw new InvalidException(username + " is already linked to " + whitelist + ".");
        persistenceManager.insertUserToWhitelistEntry(username, whitelist);
        return ok(username + " linked to " + whitelist + ".");
    }

    private ResponseEntity<?> unlinkUserFromWhitelist(JsonObject bodyJson) throws InvalidException {
        String username = retrieveUsername(bodyJson, true, true);
        String whitelist = retrieveWhitelist(bodyJson, true, true);
        if (!persistenceManager.userToWhitelistExists(username, whitelist))
            throw new InvalidException(username + " is already unlinked from " + whitelist + ".");
        persistenceManager.deleteUserToWhitelistEntry(username, whitelist);
        return ok(username + " unlinked from " + whitelist + ".");
    }

    private ResponseEntity<?> deleteUser(JsonObject bodyJson) throws InvalidException {
        String username = retrieveUsername(bodyJson, true, true);
        persistenceManager.deleteUserToWhitelistEntriesOfUser(username);
        userDetailsManager.deleteUser(username);
        return ok().body(username + " deleted.");
    }

    private ResponseEntity<?> createUser(JsonObject bodyJson) throws InvalidException {
        String username = retrieveUsername(bodyJson, true, false);
        if(userDetailsManager.userExists(username))
            throw new InvalidException(username + " already exists.");
        String password = retrievePassword(bodyJson, true);

        // retrieve optional role from json
        List<GrantedAuthority> authorities = new ArrayList<>();
        String role = retrieveRole(bodyJson, false);
        switch (role) {
            case ROLE_ADMIN:
                authorities.add(new SimpleGrantedAuthority(ROLE_ADMIN));
            case ROLE_MEMBER:
                authorities.add(new SimpleGrantedAuthority(ROLE_MEMBER));
            default:
                authorities.add(new SimpleGrantedAuthority(ROLE_USER));
        }

        // retrieve optional whitelist from json
        String whitelist = retrieveWhitelist(bodyJson, false, true);

        // create user
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(username,
                new BCryptPasswordEncoder().encode(password), authorities);
        userDetailsManager.createUser(userDetails);

        // link to whitelist(s)
        switch (role) {
            case ROLE_ADMIN:
                persistenceManager.insertUserToWhitelistEntry(username, DEFAULT_ADMIN_WHITELIST);
            case ROLE_MEMBER:
                persistenceManager.insertUserToWhitelistEntry(username, DEFAULT_WRITE_WHITELIST);
            default:
                persistenceManager.insertUserToWhitelistEntry(username, DEFAULT_READ_WHITELIST);
        }
        if(whitelist == null) {
            return ok(username + " created.");
        } else {
            persistenceManager.insertUserToWhitelistEntry(username, whitelist);
            return ok(username + " created and linked to " + whitelist + ".");
        }
    }

    private ResponseEntity<?> setRole(JsonObject bodyJson) throws InvalidException {
        String username = retrieveUsername(bodyJson, true, true);
        String newRole = retrieveRole(bodyJson, true);
        String oldRole = getRole(username);
        if(oldRole.equals(newRole))
            throw new InvalidException(newRole + " is already set for " + username + ".");
        List<GrantedAuthority> authorities = new ArrayList<>();
        switch (newRole) {
            case ROLE_ADMIN:
                authorities.add(new SimpleGrantedAuthority(ROLE_ADMIN));
            case ROLE_MEMBER:
                authorities.add(new SimpleGrantedAuthority(ROLE_MEMBER));
            default:
                authorities.add(new SimpleGrantedAuthority(ROLE_USER));
        }
        UserDetails user = userDetailsManager.loadUserByUsername(username);
        userDetailsManager.updateUser(new org.springframework.security.core.userdetails.User(username,
                user.getPassword(), authorities));
        boolean readOnly = true;
        switch (newRole) {
            case ROLE_ADMIN:
                if(!persistenceManager.userToWhitelistExists(username, DEFAULT_ADMIN_WHITELIST))
                    persistenceManager.insertUserToWhitelistEntry(username, DEFAULT_ADMIN_WHITELIST);
            case ROLE_MEMBER:
                if(oldRole.equalsIgnoreCase(ROLE_USER) && !persistenceManager.userToWhitelistExists(username, DEFAULT_WRITE_WHITELIST))
                    persistenceManager.insertUserToWhitelistEntry(username, DEFAULT_WRITE_WHITELIST);
                readOnly = false;
            default:
                if(oldRole.equalsIgnoreCase(ROLE_ADMIN) && persistenceManager.userToWhitelistExists(username, DEFAULT_ADMIN_WHITELIST))
                    persistenceManager.deleteUserToWhitelistEntry(username, DEFAULT_ADMIN_WHITELIST);
                if(readOnly && persistenceManager.userToWhitelistExists(username, DEFAULT_WRITE_WHITELIST))
                    persistenceManager.deleteUserToWhitelistEntry(username, DEFAULT_WRITE_WHITELIST);
        }
        return ok(newRole + " set for " + username);
    }

    private String getRole(String username) {
        String role = ROLE_USER;
        UserDetails user = userDetailsManager.loadUserByUsername(username);
        for(GrantedAuthority authority : user.getAuthorities()) {
            String tmp = authority.getAuthority();
            if(tmp.equalsIgnoreCase(ROLE_ADMIN)) {
                role = ROLE_ADMIN;
                break;
            } else if(tmp.equalsIgnoreCase(ROLE_MEMBER))
                role = ROLE_MEMBER;
        }
        return role;
    }

    /* Parsing body content */

    private String retrieveFunction(JsonObject bodyJson, boolean required) throws InvalidException {
        if (bodyJson.has("function")) {
            return bodyJson.get("function").toString().replace("\"","");
        } else if(required)
            throw new InvalidException("Function required.");
        else return null;
    }

    private String retrieveRole(JsonObject bodyJson, boolean required) throws InvalidException {
        if (bodyJson.has("role")) {
            String role = bodyJson.get("role").toString().replace("\"","").toUpperCase();
            if(!(role.equals(ROLE_USER) || role.equals(ROLE_MEMBER) || role.equals(ROLE_ADMIN)))
                throw new InvalidException("Invalid role definition. " +
                        "Please choose either ROLE_USER, ROLE_MEMBER, or ROLE_ADMIN!");
            else return role;
        } else if(required)
            throw new RequiredException("Role required.");
        else return ROLE_USER;
    }

    private String retrieveWhitelist(JsonObject bodyJson, boolean required, boolean existing) throws InvalidException {
        String whitelist;
        if (bodyJson.has("whitelist")) {
            whitelist = bodyJson.get("whitelist").toString().replace("\"","");
        } else if(required)
            throw new RequiredException("Whitelist required.");
        else return null;
        if(existing && !persistenceManager.whitelistExists(whitelist))
            throw new InvalidException("Whitelist " + whitelist + " does not exist.");
        else return whitelist;
    }

    private String retrieveUsername(JsonObject bodyJson, boolean required, boolean existing) throws InvalidException {
        String username;
        if (bodyJson.has("username"))
            username = bodyJson.get("username").toString().replace("\"","");
        else if (bodyJson.has("user"))
            username = bodyJson.get("user").toString().replace("\"","");
        else if (bodyJson.has("name"))
            username = bodyJson.get("name").toString().replace("\"","");
        else if(required)
            throw new RequiredException("Username required.");
        else return null;
        if(existing && !userDetailsManager.userExists(username))
            throw new InvalidException("Username " + username + " does not exist.");
        else return username;
    }

    private String retrievePassword(JsonObject bodyJson, boolean required) throws InvalidException {
        String password = null;
        if (bodyJson.has("password"))
            password = bodyJson.get("password").toString().replace("\"","");
        else if (bodyJson.has("pass"))
            password = bodyJson.get("pass").toString().replace("\"","");
        else if(required)
            throw new RequiredException("Password required.");
        if(password != null && password.length() < 8)
            throw new InvalidException("Passwords must be at least 8 characters long.");
        return password;
    }

    /* End of parsing body content */

    /* Custom Exceptions */

    private class RequiredException extends RuntimeException {
        RequiredException(String msg) {
            super(msg);
        }
    }

    private class InvalidException extends Exception {
        InvalidException(String msg) {
            super(msg);
        }
    }
}
