package de.nutrisafe.functionrights;

import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FunctionRightFilter extends GenericFilterBean {

    private final FunctionRightProvider functionRightProvider;

    public FunctionRightFilter(FunctionRightProvider functionRightProvider) {
        this.functionRightProvider = functionRightProvider;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {
        if (!functionRightProvider.validateFunction(req)) {
            ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
        filterChain.doFilter(req, res);
    }

}