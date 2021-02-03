package de.nutrisafe;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowCountCallbackHandler;
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
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;

@Configuration
@SuppressFBWarnings("OBL_UNSATISFIED_OBLIGATION_EXCEPTION_EDGE")
public class UserDatabaseConfig {

    public final static String DEFAULT_ADMIN_WHITELIST = "DEFAULT_ADMIN_WHITELIST";
    public final static String DEFAULT_WRITE_WHITELIST = "DEFAULT_WRITE_WHITELIST";
    public final static String DEFAULT_READ_WHITELIST = "DEFAULT_READ_WHITELIST";
    public final static String ROLE_ADMIN = "ROLE_ADMIN";
    public final static String ROLE_MEMBER = "ROLE_MEMBER";
    public final static String ROLE_USER = "ROLE_USER";

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
        jdbcTemplate.execute("create table if not exists whitelist (name varchar(128) primary key)");
        jdbcTemplate.execute("create table if not exists user_to_whitelist (username varchar(128) references users(username), whitelist varchar(128) references whitelist(name))");
        jdbcTemplate.execute("create table if not exists function (name varchar(128) not null, whitelist varchar(128) references whitelist(name))");

        // check for existence of default whitelists
        if(!whitelistExists(DEFAULT_READ_WHITELIST, jdbcTemplate)) {
            System.out.print("[NutriSafe REST API] UserDatabaseConfig: No default read whitelist found: Creating new list... ");
            jdbcTemplate.execute("insert into whitelist(name) values ('" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('objectExists', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('privateObjectExists', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('readObject', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('readAccept', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_readMetaDef', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('getUserInfo', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('updatePassword', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('pollingResult', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('selectChaincode', '" + DEFAULT_READ_WHITELIST + "')");
            System.out.println("done!");
        }
        if(!whitelistExists(DEFAULT_WRITE_WHITELIST, jdbcTemplate)) {
            System.out.print("[NutriSafe REST API] UserDatabaseConfig: No default write whitelist found: Creating new list... ");
            jdbcTemplate.execute("insert into whitelist(name) values ('" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('deleteObject', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('createObject', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('setReceiver', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('changeOwner', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('addPredecessor', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('updateAttribute', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('addRuleNameAndCondition', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('deleteRuleForProduct', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('activateAlarm', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('deactivateAlarm', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('exportDataToAuthPDC', '" + DEFAULT_WRITE_WHITELIST + "')");
            System.out.println("done!");
        }
        if(!whitelistExists(DEFAULT_ADMIN_WHITELIST, jdbcTemplate)) {
            System.out.print("[NutriSafe REST API] UserDatabaseConfig: No default admin whitelist found: Creating new list... ");
            jdbcTemplate.execute("insert into whitelist(name) values ('" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_createSampleData', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_addAttributeDefinition', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_addProductDefinition', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_addUnit', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('createUser', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('deleteUser', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('setRole', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('createWhitelist', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('deleteWhitelist', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('linkFunctionToWhitelist', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('unlinkFunctionFromWhitelist', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('linkUserToWhitelist', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('unlinkUserFromWhitelist', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('getUserInfoOfUser', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('getWhitelists', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('getWhitelist', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('getAllUsers', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('getFunctions', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('getUsersByAuthority', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('selectDatabase', '" + DEFAULT_ADMIN_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_deleteProduct', '" + DEFAULT_ADMIN_WHITELIST + "')");

            System.out.println("done!");
        }

        // TODO: creation of test users... needs to be deleted for production!
        UserDetailsManager userDetailsManager = userDetailsManager();
        if(!userDetailsManager.userExists("nutriuser")) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(ROLE_USER));
            authorities.add(new SimpleGrantedAuthority(ROLE_MEMBER));
            UserDetails user = new org.springframework.security.core.userdetails.User("nutriuser",
                    new BCryptPasswordEncoder().encode("12345678"), authorities);
            userDetailsManager.createUser(user);
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('nutriuser', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('nutriuser', '" + DEFAULT_WRITE_WHITELIST + "')");
            Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        if(!userDetailsManager.userExists("public")) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(ROLE_USER));
            UserDetails user = new org.springframework.security.core.userdetails.User("public",
                    new BCryptPasswordEncoder().encode("12345678"), authorities);
            userDetailsManager.createUser(user);
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('public', '" + DEFAULT_READ_WHITELIST + "')");
            Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        if(!userDetailsManager.userExists("admin")) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(ROLE_USER));
            authorities.add(new SimpleGrantedAuthority(ROLE_MEMBER));
            authorities.add(new SimpleGrantedAuthority(ROLE_ADMIN));
            UserDetails user = new org.springframework.security.core.userdetails.User("admin",
                    new BCryptPasswordEncoder().encode("12345678"), authorities);
            userDetailsManager.createUser(user);
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('admin', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('admin', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('admin', '" + DEFAULT_ADMIN_WHITELIST + "')");
            Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // TODO: end of test users.. don't forget to delete this!

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


    private boolean whitelistExists(String whitelist, JdbcTemplate jdbcTemplate) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator whitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from whitelist where name = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(whitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }
}
