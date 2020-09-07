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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowCountCallbackHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.util.*;

import static de.nutrisafe.UserDatabaseConfig.*;
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
    @Autowired
    UserDetailsManager userDetailsManager;
    @Autowired
    JdbcTemplate jdbcTemplate;

    @GetMapping(value = "/get", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> get(@RequestParam String function, @RequestParam(required = false) String[] args) {

        try {
            User user = persistenceManager.getCurrentUser();
            if(user == null)
                throw new UsernameNotFoundException("Username not found");
            else {
                String response = helper.evaluateTransaction(config, function, args);
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
            String response = helper.evaluateTransaction(config,"queryChaincodeByQueryString", args);
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
                return switch (function) {
                    case "addUser" -> addUser(bodyJson);
                    case "addFunctionToWhitelist" -> addFunctionToWhitelist(bodyJson);
                    case "removeFunctionFromWhitelist" -> removeFunctionFromWhitelist(bodyJson);
                    case "deleteUser" -> deleteUser(bodyJson);
                    default -> hyperledgerSubmit(function, bodyJson);
                };
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

    private ResponseEntity<?> hyperledgerSubmit(String function, JsonObject bodyJson) {
        try {
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
        } catch (FileNotFoundException e) {
            return badRequest().body("REST API was unable to load the key defs for possible functions. " +
                    "Please contact the administrator.");
        } catch (IOException e) {
            return badRequest().body("REST API was unable to parse the key defs file for possible functions. " +
                    "Please contact the administrator.");
        }
    }

    private ResponseEntity<?> removeFunctionFromWhitelist(JsonObject bodyJson) {
        String whitelist;
        String function;
        boolean whitelistDeleted;
        if (bodyJson.has("whitelist")) {
            whitelist = bodyJson.get("whitelist").toString().replace("\"","");
        } else
            return badRequest().body("Whitelist entry missing in JSON.");
        if (bodyJson.has("function")) {
            function = bodyJson.get("function").toString().replace("\"","");
        } else
            return badRequest().body("Function entry missing in JSON.");
        if(!whitelistExists(whitelist))
            return badRequest().body("Whitelist does not exist.");
        PreparedStatementCreator functionDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from function where name = ? and whitelist = ?");
            preparedStatement.setString(1, function);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(functionDeleteStatement);
        if(!hasWhitelistAnyFunctions(whitelist) && !hasWhitelistAnyUsers(whitelist)) {
            PreparedStatementCreator whitelistDeleteStatement = connection -> {
                PreparedStatement preparedStatement = connection.prepareStatement("delete from whitelist where name = ? and whitelist = ?");
                preparedStatement.setString(1, function);
                preparedStatement.setString(2, whitelist);
                return preparedStatement;
            };
            jdbcTemplate.update(whitelistDeleteStatement);
            return ok(function + " successfully removed and unused " + whitelist + " deleted");
        } else
            return ok(function + " successfully removed from " + whitelist);
    }

    private ResponseEntity<?> addFunctionToWhitelist(JsonObject bodyJson) {
        String whitelist;
        String function;
        boolean whitelistExisted;
        if (bodyJson.has("whitelist")) {
            whitelist = bodyJson.get("whitelist").toString().replace("\"","");
        } else
            return badRequest().body("Whitelist entry missing in JSON.");
        if (bodyJson.has("function")) {
            function = bodyJson.get("function").toString().replace("\"","");
        } else
            return badRequest().body("Function entry missing in JSON.");
        if(functionToWhitelistEntryExists(function, whitelist))
            return ok().body("Entry already registered. No new entry created.");
        whitelistExisted = whitelistExists(whitelist);
        if(!whitelistExisted) {
            PreparedStatementCreator whitelistInsertStatement = connection -> {
                PreparedStatement preparedStatement = connection.prepareStatement("insert into whitelist(name) values (?)");
                preparedStatement.setString(1, whitelist);
                return preparedStatement;
            };
            jdbcTemplate.update(whitelistInsertStatement);
        }
        return whitelistExisted ? ok(function + " added to " + whitelist) : ok(whitelist + " created and " + function + " added");
    }

    private ResponseEntity<?> deleteUser(JsonObject bodyJson) {
        String username;
        if (bodyJson.has("username")) {
            username = bodyJson.get("username").toString().replace("\"","");
        } else if (bodyJson.has("user")) {
            username = bodyJson.get("user").toString().replace("\"","");
        } else if (bodyJson.has("name")) {
            username = bodyJson.get("name").toString().replace("\"","");
        } else
            return badRequest().body("Username required");
        if(!userDetailsManager.userExists(username))
            return ok().body("User does not exist.");
        PreparedStatementCreator userToWhitelistDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from user_to_whitelist where username = ?");
            preparedStatement.setString(1, username);
            return preparedStatement;
        };
        jdbcTemplate.update(userToWhitelistDeleteStatement);
        userDetailsManager.deleteUser(username);
        return ok().body("User successfully deleted.");
    }

    private ResponseEntity<?> addUser(JsonObject bodyJson) {
        // retrieve username from json
        String username;
        if (bodyJson.has("username")) {
            username = bodyJson.get("username").toString().replace("\"","");
        } else if (bodyJson.has("user")) {
            username = bodyJson.get("user").toString().replace("\"","");
        } else if (bodyJson.has("name")) {
            username = bodyJson.get("name").toString().replace("\"","");
        } else
            return badRequest().body("Username required");

        // retrieve password from json
        String password;
        if (bodyJson.has("password")) {
            password = bodyJson.get("password").toString().replace("\"","");
        } else if (bodyJson.has("pass")) {
            password = bodyJson.get("pass").toString().replace("\"","");
        } else
            return badRequest().body("Password required");

        // retrieve role from json
        int roleState = 0;
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(ROLE_USER));
        if (bodyJson.has("role")) {
            String role = bodyJson.get("role").toString().replace("\"","");
            if(role.equalsIgnoreCase(ROLE_MEMBER)) {
                roleState = 1;
                authorities.add(new SimpleGrantedAuthority(ROLE_MEMBER));
            } else if(role.equalsIgnoreCase(ROLE_ADMIN)) {
                roleState = 2;
                authorities.add(new SimpleGrantedAuthority(ROLE_MEMBER));
                authorities.add(new SimpleGrantedAuthority(ROLE_ADMIN));
            } else if(!role.equalsIgnoreCase(ROLE_USER))
                return badRequest().body("Invalid role name! Choose either ROLE_USER, ROLE_MEMBER, or ROLE_ADMIN.");
        }

        UserDetails userDetails = new org.springframework.security.core.userdetails.User(username,
                new BCryptPasswordEncoder().encode(password), authorities);
        userDetailsManager.createUser(userDetails);

        switch (roleState) {
            case 2:
                PreparedStatementCreator whitelistInsertStatement = connection -> {
                    PreparedStatement preparedStatement = connection.prepareStatement("insert into user_to_whitelist(username, whitelist) values (?, '"
                            + DEFAULT_ADMIN_WHITELIST + "')");
                    preparedStatement.setString(1, username);
                    return preparedStatement;
                };
                jdbcTemplate.update(whitelistInsertStatement);
            case 1:
                whitelistInsertStatement = connection -> {
                    PreparedStatement preparedStatement = connection.prepareStatement("insert into user_to_whitelist(username, whitelist) values (?, '"
                            + DEFAULT_WRITE_WHITELIST + "')");
                    preparedStatement.setString(1, username);
                    return preparedStatement;
                };
                jdbcTemplate.update(whitelistInsertStatement);
            default:
                whitelistInsertStatement = connection -> {
                    PreparedStatement preparedStatement = connection.prepareStatement("insert into user_to_whitelist(username, whitelist) values (?, '"
                            + DEFAULT_READ_WHITELIST + "')");
                    preparedStatement.setString(1, username);
                    return preparedStatement;
                };
                jdbcTemplate.update(whitelistInsertStatement);
        }

        return ok(username + " successfully created");
    }

    private boolean whitelistExists(String whitelist) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator whitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from whitelist where name = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(whitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    private boolean functionToWhitelistEntryExists(String function, String whitelist) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator functionToWhitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from function where name = ? and whitelist = ?");
            preparedStatement.setString(1, function);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(functionToWhitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    private boolean hasWhitelistAnyFunctions(String whitelist) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator functionToWhitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from function where whitelist = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(functionToWhitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    private boolean hasWhitelistAnyUsers(String whitelist) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator userToWhitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from user_to_whitelist where whitelist = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(userToWhitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }
}
