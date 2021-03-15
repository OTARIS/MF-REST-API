package de.metahlfabric.functionrights;

import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The FunctionRightFilter utilizes a {@link FunctionRightProvider} in order to filter requests based on allowed function
 * calls according to the whitelist entries.
 * <p>
 * Instantiate this and add it to the
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} filter chain.
 *
 * @author Dennis Lamken
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