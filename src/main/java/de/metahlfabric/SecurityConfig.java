package de.metahlfabric;

import de.metahlfabric.authtoken.JwtTokenProvider;
import de.metahlfabric.authtoken.OAuthTokenProvider;
import de.metahlfabric.authtoken.TokenConfigurer;
import de.metahlfabric.functionrights.FunctionRightConfigurer;
import de.metahlfabric.functionrights.FunctionRightProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * This class sets rules for authorization based on roles as well as additional filters like the one defined by the
 * {@link TokenConfigurer}.
 *
 * @author Dennis Lamken, Tobias Wagner, Kathrin Kleinhammer
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
@Configuration
@DependsOn("jwtTokenProvider")
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private OAuthTokenProvider oAuthTokenProvider;
    @Autowired
    private FunctionRightProvider functionRightProvider;
    @Value("${security.oauth2.resourceserver.jwk.key-set-uri}")
    String url;

    @Lazy
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorize -> authorize
                .antMatchers("/auth").permitAll()
                .antMatchers("/get").hasAuthority("ROLE_USER")
                .antMatchers("/select").hasAuthority("ROLE_USER")
                .antMatchers("/submit").hasAuthority("ROLE_USER")
                .antMatchers("/events").hasAuthority("ROLE_USER")
        ).formLogin().disable().csrf().disable().apply(new TokenConfigurer(jwtTokenProvider, oAuthTokenProvider)).and()
                //.oauth2ResourceServer(oauth2 -> oauth2.jwt())
                .apply(new FunctionRightConfigurer(functionRightProvider));
        http.cors();
    }

    @Autowired
    public void configAuthentication(AuthenticationManagerBuilder builder)
            throws Exception {
        builder.userDetailsService(userDetailsService);
    }

    @Lazy
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
        return NimbusJwtDecoder.withJwkSetUri(url).build();
    }

}
