package de.nutrisafe.authtoken;

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
 * <p>
 * Instantiate this and add it to the
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} filter chain.
 *
 * @author Dennis Lamken
 */
public class TokenFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;
    private final OAuthTokenProvider oAuthTokenProvider;

    public TokenFilter(JwtTokenProvider jwtTokenProvider, OAuthTokenProvider oAuthTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.oAuthTokenProvider = oAuthTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) req);
        Authentication auth = null;
        if (token != null) {
            if (jwtTokenProvider.validateToken(token))
                auth = jwtTokenProvider.getAuthentication(token);
            else {
                String extUsername = oAuthTokenProvider.getExternalUsername(token);
                if (extUsername != null)
                    auth = oAuthTokenProvider.getAuthentication(extUsername);
            }
        }
        SecurityContextHolder.getContext().setAuthentication(auth);
        if (auth == null) {
            ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            ((HttpServletResponse) res).setHeader("Reason", "Invalid Token");
        }
        filterChain.doFilter(req, res);
    }

}