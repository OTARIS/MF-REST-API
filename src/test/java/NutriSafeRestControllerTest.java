import com.google.gson.Gson;
import de.nutrisafe.NutriSafeRestController;
import de.nutrisafe.UserDatabaseConfig;
import de.nutrisafe.jwt.JwtTokenProvider;
import org.junit.BeforeClass;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static de.nutrisafe.UserDatabaseConfig.ROLE_MEMBER;
import static de.nutrisafe.UserDatabaseConfig.ROLE_USER;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.AFTER_TEST_METHOD;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.BEFORE_TEST_METHOD;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = {NutriSafeRestController.class, UserDatabaseConfig.class})
@AutoConfigureMockMvc
@Import(de.nutrisafe.jwt.JwtTokenProvider.class)
@Transactional
@Sql({"classpath:test_init.sql"})
public class NutriSafeRestControllerTest {

    @Autowired
    private UserDetailsManager userDetailsManager;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private JdbcTemplate jdbcTemplate;


    private HashMap<Object, Object> body = new HashMap<>();
    private String token;
    private String username;
    private String whitelist;
    private String password;


    @BeforeEach
    public void init() {
        // create token
        token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));

        // create test user
        username = "testUser";
        whitelist = "TEST_WHITELIST";
        password  = "12345678";

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(ROLE_USER));
        authorities.add(new SimpleGrantedAuthority(ROLE_MEMBER));
        UserDetails user = new org.springframework.security.core.userdetails.User(username,
                new BCryptPasswordEncoder().encode(password), authorities);
        userDetailsManager.createUser(user);
    }

    @AfterEach
    public void cleanup() {
        userDetailsManager.deleteUser(username);
        body.clear();
    }

    @Test
    public void authenticationFail_wrongCredentials() throws Exception{
        body.put("username", "user_1");
        body.put("password", password);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/auth")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void authenticationSuccess() throws Exception{
        body.put("username", username);
        body.put("password", password);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/auth")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getWhitelistsSuccess() throws Exception {
        this.mockMvc.perform(get("/get?function=getWhitelists")
                .header("Authorization", "Bearer " + this.token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getWhitelistsFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        this.mockMvc.perform(get("/get?function=getWhitelists").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void getAllUsersSuccess() throws Exception {
        this.mockMvc.perform(get("/get?function=getAllUsers")
                .header("Authorization", "Bearer " + this.token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getAllUsersFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        this.mockMvc.perform(get("/get?function=getAllUsers").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void getUsersByAuthoritySuccess() throws Exception {
        this.mockMvc.perform(get("/get?function=getUsersByAuthority&args=ROLE_USER")
                .header("Authorization", "Bearer " + this.token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getUsersByAuthorityFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        this.mockMvc.perform(get("/get?function=getUsersByAuthority&args=ROLE_USER").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void getUserInfoOfUserSuccess() throws Exception {
        this.mockMvc.perform(get("/get?function=getUserInfoOfUser&args=admin")
                .header("Authorization", "Bearer " + this.token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getUserInfoFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        this.mockMvc.perform(get("/get?function=getUserInfoOfUser&args=admin").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void createAndDeleteWhitelistSuccess() throws Exception {
        body.put("whitelist", "NEW_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=createWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        mockMvc.perform(post("/submit?function=deleteWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void createWhitelistFail_wrongAuthority() throws Exception {
        body.put("whitelist", "NEW_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("testUser", Collections.singletonList("ROLE_MEMBER"));
        mockMvc.perform(post("/submit?function=createWhitelist").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    //TODO:
    @Test
    public void deleteWhitelistFail_wrongAuthority() throws Exception {
        body.put("whitelist", whitelist);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        mockMvc.perform(post("/submit?function=deleteWhitelist").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void linkAndUnlinkUserWhitelistSuccess() throws Exception {
        body.put("username", username);
        body.put("whitelist", whitelist);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=linkUserToWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        mockMvc.perform(post("/submit?function=unlinkUserFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    //@Sql(scripts = "classpath:user_to_whitelist.sql", executionPhase = BEFORE_TEST_METHOD)
    //@Sql(scripts = "classpath:user_off_whitelist.sql", executionPhase = AFTER_TEST_METHOD)
    public void linkUserToWhitelistFail_alreadyLinked() throws Exception {
        PreparedStatementCreator whitelistInsertStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("insert into " +
                    "user_to_whitelist(username, whitelist) " +
                    "values (?, ?)");
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(whitelistInsertStatement);

        body.put("username", username);
        body.put("whitelist", whitelist);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=linkUserToWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
        mockMvc.perform(post("/submit?function=unlinkUserFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void linkUserToWhitelistFail_wlDoesNotExist() throws Exception {
        body.put("username", username);
        body.put("whitelist", "NO_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=linkUserToWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void unlinkUserFromWhitelistFail_alreadyUnlinked() throws Exception {
        body.put("username", username);
        body.put("whitelist", whitelist);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=unlinkUserFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void unlinkUserFromWhitelistFail_wlDoesNotExist() throws Exception {
        body.put("username", username);
        body.put("whitelist", "TEST_WHITELIST1234");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=unlinkUserFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void createAndDeleteUserSuccess() throws Exception {
        body.put("username", "newUser");
        body.put("password", "12345678");
        body.put("role", "ROLE_MEMBER");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        mockMvc.perform(post("/submit?function=deleteUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void createAndDeleteUserFail_wrongAuthority() throws Exception {
        body.put("username", "newUser");
        body.put("password", password);
        body.put("role", "ROLE_MEMBER");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        mockMvc.perform(post("/submit?function=createUser").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
        mockMvc.perform(post("/submit?function=deleteUser").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void createUserFail_roleError() throws Exception {
        body.put("username", "newUser");
        body.put("password", password);
        body.put("role", "NO_ROLE");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void createUserFail_userExists() throws Exception {
        body.put("username", username);
        body.put("password", password);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void createUserFail_shortPwd() throws Exception {
        body.put("username", "newUser");
        body.put("password", "1234");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void createUserFail_whitelistDoesNotExist() throws Exception {
        body.put("username", "newUser");
        body.put("password", password);
        body.put("whitelist", "NO_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    //@Sql(scripts = "classpath:user_off_whitelist.sql", executionPhase = AFTER_TEST_METHOD)
    public void setRoleSuccess() throws Exception {
        body.put("username", username);
        body.put("role", "ROLE_ADMIN");
        body.put("whitelist", "DEFAULT_ADMIN_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=setRole")
                .header("Authorization", "Bearer " + this.token)
                .content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        mockMvc.perform(post("/submit?function=unlinkUserFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void setRoleFail_alreadySet() throws Exception {
        body.put("username", username);
        body.put("role", "ROLE_MEMBER");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        mockMvc.perform(post("/submit?function=setRole")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isBadRequest());
    }


}
