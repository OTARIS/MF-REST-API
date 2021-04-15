package de.metahlfabric.functionrights;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * The FunctionRightConfigurer adds a {@link FunctionRightFilter} to the
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity HttpSecurity} filter chain.
 * <p>
 * Instantiate this and apply it to the used
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} instance.
 *
 * @author Dennis Lamken
 */
public class FunctionRightConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final FunctionRightProvider functionRightProvider;

    /**
     * Uses the {@link FunctionRightProvider} in order to instantiate a new
     * {@link FunctionRightFilter} and adds it to the
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} filter chain.
     * Simply apply this instance to the used
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} instance by calling
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#apply(SecurityConfigurerAdapter)}.
     *
     * @param functionRightProvider checks if a user is allowed to call a certain function
     */
    public FunctionRightConfigurer(FunctionRightProvider functionRightProvider) {
        this.functionRightProvider = functionRightProvider;
    }

    @Override
    public void configure(HttpSecurity http) {
        FunctionRightFilter customFilter = new FunctionRightFilter(functionRightProvider);
        http.addFilterAfter(customFilter, UsernamePasswordAuthenticationFilter.class);
    }

}