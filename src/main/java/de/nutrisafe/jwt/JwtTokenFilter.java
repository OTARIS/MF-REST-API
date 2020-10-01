package de.nutrisafe.jwt;

import de.nutrisafe.functionrights.FunctionRightProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The FunctionRightFilter utilizes a {@link FunctionRightProvider} in order to filter requests based on allowed function
 * calls according to the whitelist entries.
 *
 * Instantiate this and add it to the
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} filter chain.
 *
 * @author Dennis Lamken
 */
public class JwtTokenFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) req);
        if (token != null && jwtTokenProvider.validateToken(token)) {
            Authentication auth = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        } else {
            SecurityContextHolder.getContext().setAuthentication(null);
            ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            ((HttpServletResponse) res).setHeader("Reason", "Invalid JWT Token");
        }
        filterChain.doFilter(req, res);
    }

}