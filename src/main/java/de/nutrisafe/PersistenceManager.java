package de.nutrisafe;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import java.sql.PreparedStatement;
import java.util.*;

@Lazy
@Service
public class PersistenceManager {

    private final Model modelMapper = new Model();
    @Autowired
    private UserDetailsManager userDetailsManager;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public boolean createUser(String username, String encodedPassword) {
        if(userDetailsManager == null)
            return false;
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator userSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from users where username = ?");
            preparedStatement.setString(1, username);
            return preparedStatement;
        };
        this.jdbcTemplate.query(userSelectStatement, countCallback);
        if(countCallback.getRowCount() < 1) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            UserDetails user = new org.springframework.security.core.userdetails.User(username, encodedPassword, authorities);
            userDetailsManager.createUser(user);
            Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        return true;
    }

    public boolean userExists(String name) {
        return userDetailsManager.userExists(name);
    }

    public User getCurrentUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(principal instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) principal;
            return new User(userDetails.getUsername(), userDetails.isEnabled());
        } else
            return null;
    }

    public boolean hasAuthority(User user, String authority) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator userSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from authorities where username = ? and authority = ?");
            preparedStatement.setString(1, user.getName());
            preparedStatement.setString(2, authority);
            return preparedStatement;
        };
        this.jdbcTemplate.query(userSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    public List<String> getAuthorities(String username) {
        List<GrantedAuthority> authorityObjectList = new LinkedList<>(userDetailsService.loadUserByUsername(username).getAuthorities());
        List<String> result = new ArrayList<>();
        for(GrantedAuthority authority : authorityObjectList) {
            result.add(authority.getAuthority());
        }
        return result;
    }

    public HyperledgerAccount getHyperledgerAccount(User user) {
        // TODO: decrypt Hyperledger Account with credentials
        PreparedStatementCreator userSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select hyperledgername, account, affiliation, mspId from hyperledger where username = ?");
            preparedStatement.setString(1, user.getName());
            return preparedStatement;
        };
        List<HyperledgerAccount> accounts = this.jdbcTemplate.query(userSelectStatement, modelMapper.getHyperledgerAccountRowMapper());
        return accounts.get(0);
    }

    public Set<String> getAuthorities(HyperledgerAccount account) {
        PreparedStatementCreator userSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select role from roles where hyperledgername = ?");
            preparedStatement.setString(1, account.getName());
            return preparedStatement;
        };
        return new HashSet<>(this.jdbcTemplate.query(userSelectStatement, modelMapper.getRolesRowMapper()));
    }

}