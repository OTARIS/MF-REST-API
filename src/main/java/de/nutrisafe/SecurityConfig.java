package de.nutrisafe;

import de.nutrisafe.functionrights.FunctionRightConfigurer;
import de.nutrisafe.functionrights.FunctionRightProvider;
import de.nutrisafe.jwt.JwtConfigurer;
import de.nutrisafe.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;


@Configuration
@DependsOn("jwtTokenProvider")
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private FunctionRightProvider functionRightProvider;
    @Value("${security.oauth2.resourceserver.jwk.key-set-uri}")
    String url;

    @Lazy
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorize -> authorize
                .antMatchers("/auth").permitAll()
                .antMatchers("/get").hasAuthority("ROLE_USER")
                .antMatchers("/select").hasAuthority("ROLE_USER")
                .antMatchers("/submit").hasAuthority("ROLE_USER")
        ).formLogin().disable().csrf().disable().apply(new JwtConfigurer(jwtTokenProvider)).and()
                //.oauth2ResourceServer(oauth2 -> oauth2.jwt())
                .apply(new FunctionRightConfigurer(functionRightProvider));
        http.cors();
    }

    @Autowired
    public void configAuthentication(AuthenticationManagerBuilder builder)
            throws Exception {
        builder.userDetailsService(userDetailsService);
    }

    @Lazy
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(url).build();
        return jwtDecoder;
    }

}
