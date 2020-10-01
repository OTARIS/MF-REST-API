package de.nutrisafe.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * The JwtConfigurer adds a {@link JwtTokenFilter} to the
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity HttpSecurity} filter chain.
 *
 * Instantiate this and apply it to the used
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} instance.
 *
 * @author Dennis Lamken
 */
public class JwtConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Uses the {@link JwtTokenProvider} in order to instantiate a new
     * {@link JwtTokenFilter} and adds it to the
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} filter chain.
     * Simply apply this instance to the used
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} instance by calling
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#apply(SecurityConfigurerAdapter)}.
     * @param jwtTokenProvider checks if a user is allowed to call a certain function
     */
    public JwtConfigurer(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) {
        JwtTokenFilter customFilter = new JwtTokenFilter(jwtTokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }

}