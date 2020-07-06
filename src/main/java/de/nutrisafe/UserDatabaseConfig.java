package de.nutrisafe;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

import javax.sql.DataSource;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

@Configuration
public class UserDatabaseConfig {

    @Autowired
    private Config config;

    @Lazy
    @Bean
    @DependsOn("dataSource")
    public JdbcTemplate jdbcTemplate() {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource());
        jdbcTemplate.execute("create table if not exists users (username varchar(128) primary key, password varchar(128) not null, enabled bool not null)");
        jdbcTemplate.execute("create table if not exists authorities (username varchar(128) references users(username), authority varchar(128) not null)");
        jdbcTemplate.execute("create table if not exists persistent_logins ( username varchar(128) references users(username), series varchar(64) primary key, token varchar(64) not null, last_used timestamp not null)");
        jdbcTemplate.execute("create table if not exists hyperledger (username varchar(128) references users(username), hyperledgername varchar(128) unique not null, account varchar(128), affiliation varchar(128), mspId varchar(128))");
        jdbcTemplate.execute("create table if not exists roles (hyperledgername varchar(128) references hyperledger(hyperledgername), role varchar(128) not null)");
        UserDetailsManager userDetailsManager = userDetailsManager();
        if(!userDetailsManager.userExists("nutriuser")) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            UserDetails user = new org.springframework.security.core.userdetails.User("nutriuser",
                    new BCryptPasswordEncoder().encode("12345"), authorities);
            userDetailsManager.createUser(user);
            Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        return jdbcTemplate;
    }

    @Bean
    public DataSource dataSource() {
        String databaseName = "/nutrisaferestdb";
        String url;
        Integer port = config.getDatabaseConfig().getPort();
        if(port < 1 || port > 65535) {
            System.err.println("[NutriSafe REST API] Warning: Invalid port number! Fallback to 5432");
            port = 5432;
        }
        try {
            URI.create(config.getDatabaseConfig().getHost());
            url = "jdbc:postgresql:" + config.getDatabaseConfig().getHost() + ":"
                    + port + databaseName;
        } catch (Exception e) {
            System.err.println("[NutriSafe REST API] Warning: Invalid host address! Fallback to //localhost");
            url = "jdbc:postgresql://localhost:" + port + databaseName;
        }
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl(url);
        dataSource.setUsername(config.getDatabaseConfig().getUsername());
        dataSource.setPassword(config.getDatabaseConfig().getPassword());
        return dataSource;
    }

    @Lazy
    @Bean
    @DependsOn("userDetailsManager")
    public UserDetailsService userDetailsService() {
        return userDetailsManager();
    }

    @Lazy
    @Bean
    @DependsOn("dataSource")
    public UserDetailsManager userDetailsManager() {
        return new JdbcUserDetailsManager(dataSource());
    }
}
