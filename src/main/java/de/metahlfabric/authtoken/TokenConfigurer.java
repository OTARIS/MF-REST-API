package de.metahlfabric.authtoken;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * The TokenConfigurer adds a {@link TokenFilter} to the
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity HttpSecurity} filter chain.
 *
 * Instantiate this and apply it to the used
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity HttpSecurity} instance.
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
public class TokenConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final JwtTokenProvider jwtTokenProvider;
    private final OAuthTokenProvider oAuthTokenProvider;

    /**
     * Uses the {@link JwtTokenProvider} in order to instantiate a new
     * {@link TokenFilter} and adds it to the
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} filter chain.
     * Simply apply this instance to the used
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} instance by calling
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#apply(SecurityConfigurerAdapter)}.
     *
     * @param jwtTokenProvider checks if a user is allowed to call a certain function
     */
    public TokenConfigurer(JwtTokenProvider jwtTokenProvider, OAuthTokenProvider oAuthTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.oAuthTokenProvider = oAuthTokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) {
        TokenFilter customFilter = new TokenFilter(jwtTokenProvider, oAuthTokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }

}