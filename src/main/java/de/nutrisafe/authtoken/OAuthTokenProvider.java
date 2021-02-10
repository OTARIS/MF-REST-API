package de.nutrisafe.authtoken;

import de.nutrisafe.PersistenceManager;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;

import java.util.HashMap;
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
    PersistenceManager persistenceManager;

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
        return requestOAuthUsername(token, null, body, "given_name", uriBuilder.build().getPath());
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private String requestOAuthUsername(String token, Consumer<HttpHeaders> header, LinkedMultiValueMap<String, String> body, String extUsernameKey, String uri) {
        String extUsername = null;
        WebClient.Builder webClientBuilder = WebClient.builder();
        if (header != null)
            webClientBuilder.defaultHeaders(header);
        WebClient webClient = webClientBuilder.build();
        try {
            HashMap<String, String> response = Objects.requireNonNull(webClient.post().uri(uri)
                    .accept(MediaType.ALL).contentType(MediaType.APPLICATION_FORM_URLENCODED).body(BodyInserters.fromFormData(body))
                    .exchange()
                    .block())
                    .bodyToMono(new ParameterizedTypeReference<HashMap<String, String>>(){})
                    .block();
            if (response != null && response.containsKey(extUsernameKey)) {
                extUsername = response.get(extUsernameKey);
                long exp = System.currentTimeMillis() + validityInMilliseconds;
                try {
                    exp = Long.parseLong(response.get("exp"));
                } catch (NumberFormatException e) {
                    System.out.println("[NutriSafe REST API] Could not parse expiration timestamp.");
                }
                persistenceManager.updateTokenOfExternalUser(extUsername, token, exp);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return extUsername;
    }
}
