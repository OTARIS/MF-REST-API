package de.nutrisafe.functionrights;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


public class FunctionRightConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final FunctionRightProvider functionRightProvider;

    public FunctionRightConfigurer(FunctionRightProvider functionRightProvider) {
        this.functionRightProvider = functionRightProvider;
    }

    @Override
    public void configure(HttpSecurity http) {
        FunctionRightFilter customFilter = new FunctionRightFilter(functionRightProvider);
        http.addFilterAfter(customFilter, UsernamePasswordAuthenticationFilter.class);
    }

}