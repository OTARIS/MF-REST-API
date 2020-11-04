import com.google.gson.Gson;
import de.nutrisafe.NutriSafeRestController;
import de.nutrisafe.jwt.JwtTokenProvider;
import org.junit.Before;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import java.util.Collections;
import java.util.HashMap;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = NutriSafeRestController.class)
@AutoConfigureMockMvc
@Import(de.nutrisafe.jwt.JwtTokenProvider.class)
public class NutriSafeRestControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private HashMap<Object, Object> body = new HashMap<>();

    @Before
    public void setup() {
        this.mockMvc = standaloneSetup(new NutriSafeRestController()).build();
    }

    @Test
    public void authenticationFail_wrongCredentials() throws Exception{
        body.put("username", "nutriuser");
        body.put("password", "");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("nutriuser", Collections.singletonList("ROLE_USER"));
        mockMvc.perform(post("/auth").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
        body.clear();

    }

    @Test
    public void authenticationSuccess() throws Exception{
        body.put("username", "admin");
        body.put("password", "12345678");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        mockMvc.perform(post("/auth").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        body.clear();
    }

    @Test
    public void getWhitelistsSuccess() throws Exception {
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        this.mockMvc.perform(get("/get?function=getWhitelists").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getWhitelistsFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken("nutriuser", Collections.singletonList("ROLE_MEMBER"));
        this.mockMvc.perform(get("/get?function=getWhitelists").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void getAllUsersSuccess() throws Exception {
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        this.mockMvc.perform(get("/get?function=getAllUsers").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getAllUsersFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken("nutriuser", Collections.singletonList("ROLE_MEMBER"));
        this.mockMvc.perform(get("/get?function=getAllUsers").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void getUsersByAuthoritySuccess() throws Exception {
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        this.mockMvc.perform(get("/get?function=getUsersByAuthority&args=ROLE_USER").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getUsersByAuthorityFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken("nutriuser", Collections.singletonList("ROLE_MEMBER"));
        this.mockMvc.perform(get("/get?function=getUsersByAuthority&args=ROLE_USER").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void getUserInfoOfUserSuccess() throws Exception {
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        this.mockMvc.perform(get("/get?function=getUserInfoOfUser&args=admin").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void getUserInfoFail_wrongAuthority() throws Exception {
        String token = jwtTokenProvider.createToken("nutriuser", Collections.singletonList("ROLE_MEMBER"));
        this.mockMvc.perform(get("/get?function=getUserInfoOfUser&args=admin").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void createAndDeleteWhitelistSuccess() throws Exception {
        body.put("whitelist", "TEST_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        mockMvc.perform(post("/submit?function=createWhitelist").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        mockMvc.perform(post("/submit?function=deleteWhitelist").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        body.clear();
    }

    @Test
    public void createWhitelistFail_wrongAuthority() throws Exception {
        body.put("whitelist", "TEST_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("nutriuser", Collections.singletonList("ROLE_MEMBER"));
        mockMvc.perform(post("/submit?function=createWhitelist").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
        body.clear();
    }

    @Test
    public void deleteWhitelistFail_wrongAuthority() throws Exception {
        body.put("whitelist", "DEFAULT_READ_WHITELIST");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("nutriuser", Collections.singletonList("ROLE_MEMBER"));
        mockMvc.perform(post("/submit?function=deleteWhitelist").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
        body.clear();
    }

    @Test
    public void createAndDeleteUserSuccess() throws Exception {
        body.put("username", "testuser");
        body.put("password", "12345678");
        body.put("role", "ROLE_MEMBER");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        mockMvc.perform(post("/submit?function=createUser").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        mockMvc.perform(post("/submit?function=deleteUser").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
        body.clear();
    }
}
