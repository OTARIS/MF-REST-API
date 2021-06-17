package de.metahlfabric.authtoken;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import de.metahlfabric.PersistenceManager;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
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

import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Authenticates a session token of external user credentials by checking against Google OAuth or an own OAuth server.
 *
 * @author Dennis Lamken, Kathrin Kleinhammer
 * <p>
 * Copyright 2021 OTARIS Interactive Services GmbH
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@Lazy
@Component
@DependsOn("userDetailsService")
@ComponentScan(basePackages = {"de.metahlfabric"})
public class OAuthTokenProvider {

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
        return requestOAuthUsername(token, header -> header.setBasicAuth("NutriSafe_Web_UI", "12345678"), body, "user_name", "http://localhost:8085/oauth/check_token");
    }

    private String getGoogleOAuthUsername(String token) {
        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        DefaultUriBuilderFactory uriBuilderFactory = new DefaultUriBuilderFactory("https://oauth2.googleapis.com/tokeninfo");
        UriBuilder uriBuilder = uriBuilderFactory.builder();
        uriBuilder.queryParam("id_token", token);
        return requestOAuthUsername(token, null, body, "email", uriBuilder.build().toString());
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private String requestOAuthUsername(String token, Consumer<HttpHeaders> header, LinkedMultiValueMap<String, String> body, String extUsernameKey, String uri) {
        System.out.println("[MF] Checking token validity at " + uri);
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
            JsonObject response = new Gson().fromJson(rawResponse, JsonObject.class);
            if (response != null && response.has(extUsernameKey)) {
                extUsername = persistenceManager.getSHA256Hashed(response.get(extUsernameKey).getAsString());
                // 1h
                long validityInMilliseconds = 3600000;
                long exp = System.currentTimeMillis() + validityInMilliseconds;
                try {
                    exp = response.get("exp").getAsLong() * 1000;
                } catch (NumberFormatException e) {
                    System.err.println("[MF] Could not parse expiration timestamp.");
                }
                persistenceManager.updateTokenOfExternalUser(extUsername, token, exp);
            }
        } catch (NullPointerException | NoSuchAlgorithmException e) {
            extUsername = null;
        }
        return extUsername;
    }
}
