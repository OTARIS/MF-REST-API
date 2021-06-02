package de.metahlfabric.functionrights;

import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The FunctionRightFilter utilizes a {@link FunctionRightProvider} in order to filter requests based on allowed function
 * calls according to the whitelist entries.
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
public class FunctionRightFilter extends GenericFilterBean {

    private final FunctionRightProvider functionRightProvider;

    /**
     * Simply add this instance to the used
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} filter chain by calling
     * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#addFilter(Filter)}.
     *
     * @param functionRightProvider validates if a request is allowed by the current user
     */
    public FunctionRightFilter(FunctionRightProvider functionRightProvider) {
        this.functionRightProvider = functionRightProvider;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {
        if (((HttpServletResponse) res).getHeader("Reason") == null && !functionRightProvider.validateFunction(req)) {
            ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            ((HttpServletResponse) res).setHeader("Reason", "Function not allowed!");
        } else
            filterChain.doFilter(req, res);
    }

}