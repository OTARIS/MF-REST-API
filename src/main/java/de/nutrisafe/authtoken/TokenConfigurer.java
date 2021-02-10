package de.nutrisafe.authtoken;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * The JwtConfigurer adds a {@link TokenFilter} to the
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity HttpSecurity} filter chain.
 * <p>
 * Instantiate this and apply it to the used
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} instance.
 *
 * @author Dennis Lamken
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