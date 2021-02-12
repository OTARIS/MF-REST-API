package de.nutrisafe.authtoken;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import de.nutrisafe.PersistenceManager;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.function.Consumer;

@Lazy
@Component
@DependsOn("userDetailsService")
@ComponentScan(basePackages = {"de.nutrisafe"})
public class OAuthTokenProvider {

    @Value("${security.jwt.token.expire-length:3600000}")
    private long validityInMilliseconds = 3600000; // 1h
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PersistenceManager persistenceManager;

    public String getExternalUsername(String token) {
        String extUsername = persistenceManager.getExtUsername(token);
        // Todo: flag in db: own server or Google?
        if (extUsername == null || !persistenceManager.isTokenValid(token))
            extUsername = getOwnOAuthUsername(token);
        if (extUsername == null || !persistenceManager.isTokenValid(token))
            extUsername = getGoogleOAuthUsername(token);
        return extUsername != null && persistenceManager.isTokenValid(token) ? extUsername : null;
    }

    public Authentication getAuthentication(String extUsername) {
        String username = persistenceManager.getUsernameOfExternalUser(extUsername);
        UserDetails user = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(user, "", user.getAuthorities());
    }

    private String getOwnOAuthUsername(String token) {
        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", token);
        // Todo: insecure credentials! -> config
        return requestOAuthUsername(token, header -> header.setBasicAuth("client1", "12345678"), body, "user_name", "http://localhost:8085/oauth/check_token");
    }

    private String getGoogleOAuthUsername(String token) {
        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        DefaultUriBuilderFactory uriBuilderFactoryfactory = new DefaultUriBuilderFactory("https://oauth2.googleapis.com/tokeninfo");
        UriBuilder uriBuilder = uriBuilderFactoryfactory.builder();
        uriBuilder.queryParam("id_token", token);
        return requestOAuthUsername(token, null, body, "email", uriBuilder.build().toString());
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private String requestOAuthUsername(String token, Consumer<HttpHeaders> header, LinkedMultiValueMap<String, String> body, String extUsernameKey, String uri) {
        String extUsername = null;
        WebClient.Builder webClientBuilder = WebClient.builder();
        if (header != null)
            webClientBuilder.defaultHeaders(header);
        WebClient webClient = webClientBuilder.build();
        try {
            String rawResponse = Objects.requireNonNull(webClient.post().uri(uri)
                    .accept(MediaType.APPLICATION_JSON).contentType(MediaType.APPLICATION_FORM_URLENCODED).body(BodyInserters.fromFormData(body))
                    .exchange()
                    .block())
                    .bodyToMono(String.class)
                    .block();

            System.out.println("RAW RESPONSE----->" + rawResponse);
            JsonObject response = new Gson().fromJson(rawResponse, JsonObject.class);
            System.out.println("RESPONSE----->" + response);
            if (response != null && response.has(extUsernameKey)) {
                extUsername = persistenceManager.getSHA256Hashed(response.get(extUsernameKey).getAsString());
                long exp = System.currentTimeMillis() + validityInMilliseconds;
                try {
                    exp = response.get("exp").getAsLong() * 1000;
                } catch (NumberFormatException e) {
                    System.out.println("[NutriSafe REST API] Could not parse expiration timestamp.");
                }
                persistenceManager.updateTokenOfExternalUser(extUsername, token, exp);
            }
            System.out.println("EXTUSERNAME " + extUsername);
        } catch (Exception e) {
            extUsername = null;
            e.printStackTrace();
        }
        return extUsername;
    }
}
