import com.google.gson.Gson;
import de.nutrisafe.NutriSafeRestController;
import de.nutrisafe.UserDatabaseConfig;
import de.nutrisafe.jwt.JwtTokenProvider;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.lang.reflect.Array;
import java.util.Collections;
import java.util.HashMap;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = {NutriSafeRestController.class, UserDatabaseConfig.class})
@AutoConfigureMockMvc
@Import(de.nutrisafe.jwt.JwtTokenProvider.class)
@Transactional
@Sql({"classpath:test_init.sql"})
public class NutriSafeRestControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private HashMap<Object, Object> body = new HashMap<>();
    private String token;
    private String username;
    private String whitelist;
    private String password;


    @BeforeEach
    public void init() {
        // create token
        token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        // create test user data
        username = "testUser";
        whitelist = "TEST_WHITELIST";
        password  = "12345678";
    }

    @AfterEach
    public void cleanup() {
        body.clear();
    }

    @Test
    public void authenticationFail_wrongCredentials() throws Exception{
        body.put("username", "user_1");
        body.put("password", password);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/auth")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void authenticationSuccess() throws Exception{
        body.put("username", username);
        body.put("password", password);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/auth")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void getWhitelistsSuccess() throws Exception {
        String result = mockMvc.perform(get("/get?function=getWhitelists")
                .header("Authorization", "Bearer " + this.token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void getWhitelistsFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        String result = mockMvc.perform(get("/get?function=getWhitelists").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void getAllUsersSuccess() throws Exception {
        String result = mockMvc.perform(get("/get?function=getAllUsers")
                .header("Authorization", "Bearer " + this.token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void getAllUsersFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        String result = mockMvc.perform(get("/get?function=getAllUsers").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void getUsersByAuthoritySuccess() throws Exception {
        String result = mockMvc.perform(get("/get?function=getUsersByAuthority&args=ROLE_USER")
                .header("Authorization", "Bearer " + this.token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void getUsersByAuthorityFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        String result = mockMvc.perform(get("/get?function=getUsersByAuthority&args=ROLE_USER").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void getUserInfoOfUserSuccess() throws Exception {
        String result = mockMvc.perform(get("/get?function=getUserInfoOfUser&args=admin")
                .header("Authorization", "Bearer " + this.token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void getUserInfoFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        String result = mockMvc.perform(get("/get?function=getUserInfoOfUser&args=admin").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
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
        String result = mockMvc.perform(post("/submit?function=createWhitelist").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void deleteWhitelistFail_wrongAuthority() throws Exception {
        body.put("whitelist", whitelist);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        String result = mockMvc.perform(post("/submit?function=deleteWhitelist").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void linkAndUnlinkUserWhitelistSuccess() throws Exception {
        body.put("username", username);
        body.put("whitelist", whitelist);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=linkUserToWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
        result = mockMvc.perform(post("/submit?function=unlinkUserFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    @Sql("classpath:test_init.sql")
    @Sql("classpath:user_to_whitelist.sql")
    public void linkUserToWhitelistFail_alreadyLinked() throws Exception {
        body.put("username", username);
        body.put("whitelist", whitelist);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=linkUserToWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void linkUserToWhitelistFail_wlDoesNotExist() throws Exception {
        body.put("username", username);
        body.put("whitelist", "NO_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=linkUserToWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void unlinkUserFromWhitelistFail_alreadyUnlinked() throws Exception {
        body.put("username", username);
        body.put("whitelist", whitelist);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=unlinkUserFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void unlinkUserFromWhitelistFail_wlDoesNotExist() throws Exception {
        body.put("username", username);
        body.put("whitelist", "NO_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=unlinkUserFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void createAndDeleteUserSuccess() throws Exception {
        body.put("username", "newUser");
        body.put("password", "12345678");
        body.put("role", "ROLE_MEMBER");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
        result = mockMvc.perform(post("/submit?function=deleteUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void createAndDeleteUserFail_wrongAuthority() throws Exception {
        body.put("username", "newUser");
        body.put("password", password);
        body.put("role", "ROLE_MEMBER");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        String result = mockMvc.perform(post("/submit?function=createUser").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
        result = mockMvc.perform(post("/submit?function=deleteUser").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void createUserFail_roleError() throws Exception {
        body.put("username", "newUser");
        body.put("password", password);
        body.put("role", "NO_ROLE");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void createUserFail_userExists() throws Exception {
        body.put("username", username);
        body.put("password", password);
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void createUserFail_shortPwd() throws Exception {
        body.put("username", "newUser");
        body.put("password", "1234");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void createUserFail_whitelistDoesNotExist() throws Exception {
        body.put("username", "newUser");
        body.put("password", password);
        body.put("whitelist", "NO_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=createUser")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void setRoleSuccess() throws Exception {
        body.put("username", username);
        body.put("role", "ROLE_ADMIN");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=setRole")
                .header("Authorization", "Bearer " + this.token)
                .content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void setRoleFail_alreadySet() throws Exception {
        body.put("username", username);
        body.put("role", "ROLE_MEMBER");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=setRole")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isBadRequest())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void updatePasswordSuccess() throws Exception {
        body.put("username", username);
        body.put("password", password);
        body.put("newPassword", "87654321");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        String result = mockMvc.perform(post("/submit?function=updatePassword")
                .header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void updatePasswordFail_authenticationError() throws Exception {
        body.put("username", username);
        body.put("password", "11111111");
        body.put("newPassword", "87654321");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken(username, Collections.singletonList("ROLE_MEMBER"));
        String result = mockMvc.perform(post("/submit?function=updatePassword")
                .header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void linkFunctionToWhitelistSuccess() throws Exception {
        body.put("whitelist", whitelist);
        body.put("function", "createObject");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=linkFunctionToWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    @Sql("classpath:test_init.sql")
    @Sql("classpath:function_to_whitelist.sql")
    public void linkFunctionToWhitelist_alreadyLinked() throws Exception {
        body.put("whitelist", whitelist);
        body.put("function", "createObject");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=linkFunctionToWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    @Sql("classpath:test_init.sql")
    @Sql("classpath:function_to_whitelist.sql")
    public void unlinkFunctionFromWhitelistSuccess() throws Exception {
        body.put("whitelist", whitelist);
        body.put("function", "createObject");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=unlinkFunctionFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void unlinkFunctionFromWhitelistFail_alreadyUnlinked() throws Exception {
        body.put("whitelist", whitelist);
        body.put("function", "createObject");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/submit?function=unlinkFunctionFromWhitelist")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void selectDatabaseSuccess() throws Exception {
        String[] colData = {"username", "password"};
        body.put("columns", colData);
        body.put("tableName", "users");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/select?function=selectDatabase")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void selectDatabaseFail_missingAttribute() throws Exception {
        body.put("tableName", "users");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/select?function=selectDatabase")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }

    @Test
    public void selectDatabaseFail_wrongAttribute() throws Exception {
        String[] colData = {"uname", "password"};
        body.put("columns", colData);
        body.put("tableName", "users");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String result = mockMvc.perform(post("/select?function=selectDatabase")
                .header("Authorization", "Bearer " + this.token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError())
                .andDo(print()).andReturn().getResponse().getContentAsString();
        Assert.assertNotNull(result);
        System.out.println(result);
    }
}
