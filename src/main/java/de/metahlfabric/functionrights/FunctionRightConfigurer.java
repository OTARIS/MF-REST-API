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
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity HttpSecurity} instance.
 *
 * @author Dennis Lamken
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