package de.metahlfabric;

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
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * This class configures the database and provides access to it.
 *
 * @author Dennis Lamken, Tobias Wagner, Kathrin Kleinhammer
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
@Configuration
@SuppressFBWarnings("OBL_UNSATISFIED_OBLIGATION_EXCEPTION_EDGE")
public class UserDatabaseConfig {

    public final static String DEFAULT_ADMIN_WHITELIST = "DEFAULT_ADMIN_WHITELIST";
    public final static String DEFAULT_WRITE_WHITELIST = "DEFAULT_WRITE_WHITELIST";
    public final static String DEFAULT_READ_WHITELIST = "DEFAULT_READ_WHITELIST";
    public final static String ROLE_ADMIN = "ROLE_ADMIN";
    public final static String ROLE_MEMBER = "ROLE_MEMBER";
    public final static String ROLE_USER = "ROLE_USER";
    private final static String MF_ADMIN_PW = "MF_ADMIN_PW";

    @Autowired
    DatabaseConfig dbConfig;

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
        jdbcTemplate.execute("create table if not exists external_users (username varchar(128) references users(username), extusername varchar(128), token varchar(2048) not null, valid_until timestamp not null)");

        // check for existence of default whitelists
        if (notWhitelistExists(DEFAULT_READ_WHITELIST, jdbcTemplate)) {
            System.out.print("[NutriSafe REST API] UserDatabaseConfig: No default read whitelist found: Creating new list... ");
            jdbcTemplate.execute("insert into whitelist(name) values ('" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('objectExists', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('privateObjectExists', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('readObject', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('readAccept', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_readMetaDef', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_getAttributesOfProductWithVersion', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('META_readMetaDefOfProduct', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('getUserInfo', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('updatePassword', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('pollingResult', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('selectChaincode', '" + DEFAULT_READ_WHITELIST + "')");
            System.out.println("done!");
        }
        if (notWhitelistExists(DEFAULT_WRITE_WHITELIST, jdbcTemplate)) {
            System.out.print("[NutriSafe REST API] UserDatabaseConfig: No default write whitelist found: Creating new list... ");
            jdbcTemplate.execute("insert into whitelist(name) values ('" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('deleteObject', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('createObject', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('setReceiver', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('changeOwner', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('addPredecessor', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('updateAttribute', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('updatePrivateAttribute', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('addRuleNameAndCondition', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('deleteRuleForProduct', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('activateAlarm', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('deactivateAlarm', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into function(name, whitelist) values ('exportDataToAuthPDC', '" + DEFAULT_WRITE_WHITELIST + "')");
            System.out.println("done!");
        }
        if (notWhitelistExists(DEFAULT_ADMIN_WHITELIST, jdbcTemplate)) {
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

        UserDetailsManager userDetailsManager = userDetailsManager();
        if (!userDetailsManager.userExists("admin")) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(ROLE_USER));
            authorities.add(new SimpleGrantedAuthority(ROLE_MEMBER));
            authorities.add(new SimpleGrantedAuthority(ROLE_ADMIN));
            Map<String, String> env = System.getenv();
            String pw;
            if (env.containsKey(MF_ADMIN_PW)) {
                pw = env.get(MF_ADMIN_PW);
            } else {
                if(System.getProperty("spring.profiles.active").equalsIgnoreCase("test"))
                    pw = "12345678";
                else {
                    System.out.println("[MF] Please enter your initial admin password:");
                    Scanner sc = new Scanner(System.in, StandardCharsets.UTF_8);
                    do {
                        pw = sc.nextLine();
                    } while (isPasswordInvalid(pw));
                }
            }
            UserDetails user = new org.springframework.security.core.userdetails.User("admin",
                    new BCryptPasswordEncoder().encode(pw), authorities);
            userDetailsManager.createUser(user);
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('admin', '" + DEFAULT_READ_WHITELIST + "')");
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('admin', '" + DEFAULT_WRITE_WHITELIST + "')");
            jdbcTemplate.execute("insert into user_to_whitelist(username, whitelist) values ('admin', '" + DEFAULT_ADMIN_WHITELIST + "')");
            Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        return jdbcTemplate;
    }

    private boolean isPasswordInvalid(String pw) {
        if (pw == null || pw.length() < 8) {
            System.out.println("[MF] Password is too short! Please choose a password with at least eight characters.");
            return false;
        } else
            return true;
    }

    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        String databaseName = "/" + (Main.dbName == null ? dbConfig.getDbName() : Main.dbName);
        int port = dbConfig.getDbPort();
        if (port < 1 || port > 65535) {
            System.err.println("[MF] Warning: Invalid port number! Fallback to 5432");
            port = 5432;
        }
        String driver = dbConfig.getDbDriver().toLowerCase();
        StringBuilder url = new StringBuilder("jdbc:");
        if (driver.contains("mysql")) {
            dataSource.setDriverClassName("com.mysql.jdbc.Driver");
            url.append("mysql:");
        } else if (driver.contains("maria")) {
            dataSource.setDriverClassName("org.mariadb.jdbc.Driver");
            url.append("mariadb:");
        } else if (driver.contains("db2")) {
            dataSource.setDriverClassName("com.ibm.db2.jcc.DB2Driver");
            url.append("db2:");
        } else if (driver.contains("sap") || driver.contains("hana")) {
            dataSource.setDriverClassName("com.sap.db.jdbc.Driver");
            url.append("sap:");
        } else if (driver.contains("informix")) {
            dataSource.setDriverClassName("com.informix.jdbc.IfxDriver");
            url.append("informix-sqli:");
        } else {
            if (!driver.contains("postgre"))
                System.err.println("[NutriSafe REST API] Warning: Invalid or unsupported database driver name! Fallback to PostgreSQL driver.");
            dataSource.setDriverClassName("org.postgresql.Driver");
            url.append("postgresql:");
        }
        try {
            String tmpHost = dbConfig.getDbHost();
            if (tmpHost.charAt(0) != '/')
                url.append("/");
            if (tmpHost.charAt(1) != '/')
                url.append("/");
            if (tmpHost.endsWith("/")) {
                int z = tmpHost.length() - 2;
                for (int i = z; i > 0; i--) {
                    if (tmpHost.charAt(i) != '/')
                        break;
                    else
                        z = i;
                }
                tmpHost = tmpHost.substring(0, z);
            }
            URI uri = URI.create(tmpHost);
            url.append(uri.toString());
            url.append(":");
            System.out.println("[MF] Current DB host URI: " + uri.toString());
        } catch (Exception e) {
            System.err.println("[MF] Warning: Invalid host address! Fallback to //localhost");
            url.append("//localhost:");
        }
        url.append(port);
        url.append(databaseName);
        dataSource.setUrl(url.toString());
        dataSource.setUsername(Main.dbUser == null ? dbConfig.getDbUser() : Main.dbUser);
        dataSource.setPassword(Main.dbPass == null ? dbConfig.getDbPassword() : Main.dbPass);
        System.out.println("[MF] Initialize " + databaseName + "\n  with user "
                + dbConfig.getDbUser());
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

    private boolean notWhitelistExists(String whitelist, JdbcTemplate jdbcTemplate) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator whitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from whitelist where name = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(whitelistSelectStatement, countCallback);
        return countCallback.getRowCount() <= 0;
    }
}
