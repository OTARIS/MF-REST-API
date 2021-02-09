package de.nutrisafe.authtoken;

import de.nutrisafe.PersistenceManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;

@Lazy
@Component
@DependsOn("userDetailsService")
@ComponentScan(basePackages = {"de.nutrisafe"})
public class OAuthTokenProvider {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    PersistenceManager persistenceManager;

    public String getExternalUsername(String token) {
        String username = getOwnOAuthUsername(token);
        if (username == null)
            username = getGoogleOAuthUsername(token);
        return username;
    }

    public Authentication getAuthentication(String extUsername) {
        String username = persistenceManager.getUsernameOfExternalUser(extUsername);
        UserDetails user = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(user, "", user.getAuthorities());
    }

    private String getOwnOAuthUsername(String token) {
        String extUsername = null;
        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", token);
        WebClient webClient = WebClient.builder()
                // Todo: insecure credentials! -> config
                .defaultHeaders(header -> header.setBasicAuth("client1", "12345678"))
                .build();
        try {
            HashMap response = webClient.post().uri("http://localhost:8085/oauth/check_token")
                    .accept(MediaType.ALL).contentType(MediaType.APPLICATION_FORM_URLENCODED).body(BodyInserters.fromFormData(body))
                    .exchange()
                    .block()
                    .bodyToMono(HashMap.class)
                    .block();
            if (response.containsKey("user_name")) {
                extUsername = response.get("user_name").toString();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return extUsername;
    }

    private String getGoogleOAuthUsername(String token) {
        String extUsername = null;
        WebClient webClient = WebClient.builder()
                .build();
        try {
            HashMap response = webClient.post().uri("https://oauth2.googleapis.com/tokeninfo?id_token={token}", token)
                    .accept(MediaType.ALL).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .exchange()
                    .block()
                    .bodyToMono(HashMap.class)
                    .block();
            if (response != null && response.containsKey("given_name")) {
                extUsername = response.get("given_name").toString(); // TODO: set a different name
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return extUsername;
    }
}
