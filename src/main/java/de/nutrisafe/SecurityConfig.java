package de.nutrisafe;

import de.nutrisafe.functionrights.FunctionRightConfigurer;
import de.nutrisafe.functionrights.FunctionRightProvider;
import de.nutrisafe.jwt.JwtConfigurer;
import de.nutrisafe.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
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
        ).formLogin().disable().csrf().disable().apply(new JwtConfigurer(jwtTokenProvider))
                .and().apply(new FunctionRightConfigurer(functionRightProvider));
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


}
