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
    public void testAuthFail() throws Exception{
        body.put("username", "nutriuser");
        body.put("password", "");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("nutriuser", Collections.singletonList("ROLE_USER"));
        mockMvc.perform(post("/auth").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().is4xxClientError());
    }

    @Test
    public void testAuthSuccess() throws Exception{
        body.put("username", "admin");
        body.put("password", "12345678");
        Gson gson = new Gson();
        String json = gson.toJson(body);
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        mockMvc.perform(post("/auth").header("Authorization", "Bearer " + token).content(json)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }

    @Test
    public void testGetAllUsersSuccess() throws Exception {
        String token = jwtTokenProvider.createToken("admin", Collections.singletonList("ROLE_ADMIN"));
        this.mockMvc.perform(get("/get?function=getWhitelists").header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON_VALUE)).andExpect(status().isOk());
    }
}
