package de.metahlfabric.authtoken;

import de.metahlfabric.functionrights.FunctionRightProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The TokenFilter utilizes a {@link JwtTokenProvider} and an {@link OAuthTokenProvider} in order to filter invalid
 * tokens in requests.
 *
 * Instantiate this and add it to the
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity HttpSecurity} filter chain.
 *
 * @author Dennis Lamken
 *
 * Copyright 2021 OTARIS Interactive Services GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
public class TokenFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;
    private final OAuthTokenProvider oAuthTokenProvider;

    public TokenFilter(JwtTokenProvider jwtTokenProvider, OAuthTokenProvider oAuthTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.oAuthTokenProvider = oAuthTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) req);
        Authentication auth = null;
        if (token != null) {
            if (jwtTokenProvider.validateToken(token)) {
                System.out.println("[MF] Password related token found.");
                auth = jwtTokenProvider.getAuthentication(token);
            } else {
                String extUsername = oAuthTokenProvider.getExternalUsername(token);
                if (extUsername != null) {
                    System.out.println("[MF] OAuth token found.");
                    auth = oAuthTokenProvider.getAuthentication(extUsername);
                }
            }
        }
        SecurityContextHolder.getContext().setAuthentication(auth);
        if (auth == null) {
            System.err.println("[MF] Invalid token.");
            ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            ((HttpServletResponse) res).setHeader("Reason", "Invalid token");
        } else
            System.out.println("[MF] Valid token.");
        filterChain.doFilter(req, res);
    }

}