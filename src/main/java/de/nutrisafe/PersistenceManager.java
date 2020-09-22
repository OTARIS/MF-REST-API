package de.nutrisafe;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

@Lazy
@Service
public class PersistenceManager {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public User getCurrentUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(principal instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) principal;
            return new User(userDetails.getUsername(), userDetails.isEnabled());
        } else
            return null;
    }

    public List<String> getAuthorities(String username) {
        List<GrantedAuthority> authorityObjectList = new LinkedList<>(userDetailsService.loadUserByUsername(username).getAuthorities());
        List<String> result = new ArrayList<>();
        for(GrantedAuthority authority : authorityObjectList) {
            result.add(authority.getAuthority());
        }
        return result;
    }

    /* Database helper functions */

    List<String> selectAllUsers() {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select username from users");
            return preparedStatement;
        };
        List<String> whitelists = this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
        return whitelists;
    }

    List<String> selectUserToWhitelistEntriesOfUser(final String username) {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select whitelist from user_to_whitelist where username = ?");
            preparedStatement.setString(1, username);
            return preparedStatement;
        };
        List<String> whitelists = this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
        return whitelists;
    }

    List<String> selectFunctionToWhitelistEntriesOfWhitelist(final String whitelist) {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select name from function where whitelist = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        List<String> functions = this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
        return functions;
    }

    List<String> selectAllWhitelists() {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select name from whitelist");
            return preparedStatement;
        };
        List<String> whitelists = this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
        return whitelists;
    }

    void deleteWhitelistEntry(final String whitelist) {
        PreparedStatementCreator whitelistDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from whitelist where name = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(whitelistDeleteStatement);
    }

    void deleteUserToWhitelistEntriesOfUser(final String username) {
        PreparedStatementCreator userToWhitelistDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from user_to_whitelist where username = ?");
            preparedStatement.setString(1, username);
            return preparedStatement;
        };
        jdbcTemplate.update(userToWhitelistDeleteStatement);
    }

    void deleteUserToWhitelistEntriesOfWhitelist(final String whitelist) {
        PreparedStatementCreator userToWhitelistDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from user_to_whitelist where whitelist = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(userToWhitelistDeleteStatement);
    }

    void deleteUserToWhitelistEntry(final String username, final String whitelist) {
        PreparedStatementCreator userToWhitelistDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from user_to_whitelist where username = ? and whitelist = ?");
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(userToWhitelistDeleteStatement);
    }

    void deleteFunctionToWhitelistEntriesOfWhitelist(String whitelist) {
        PreparedStatementCreator functionDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from function where whitelist = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(functionDeleteStatement);
    }

    void deleteFunctionToWhitelistEntry(final String function, final String whitelist) {
        PreparedStatementCreator functionDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from function where name = ? and whitelist = ?");
            preparedStatement.setString(1, function);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(functionDeleteStatement);
    }

    void insertWhitelist(final String whitelist) {
        PreparedStatementCreator whitelistInsertStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("insert into whitelist(name) values (?)");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(whitelistInsertStatement);
    }

    void insertUserToWhitelistEntry(final String username, final String whitelist) {
        PreparedStatementCreator whitelistInsertStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("insert into " +
                    "user_to_whitelist(username, whitelist) " +
                    "values (?, ?)");
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(whitelistInsertStatement);
    }

    void insertFunctionToWhitelistEntry(final String function, final String whitelist) {
        PreparedStatementCreator whitelistInsertStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("insert into " +
                    "function(name, whitelist) " +
                    "values (?, ?)");
            preparedStatement.setString(1, function);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.update(whitelistInsertStatement);
    }

    /* End of database helper functions */

    /* Database checks */

    boolean whitelistExists(String whitelist) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator whitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from whitelist " +
                    "where name = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(whitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    boolean functionToWhitelistEntryExists(String function, String whitelist) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator functionToWhitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from function " +
                    "where name = ? and whitelist = ?");
            preparedStatement.setString(1, function);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(functionToWhitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    boolean userToWhitelistExists(String username, String whitelist) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator userToWhitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from user_to_whitelist " +
                    "where username = ? and whitelist = ?");
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, whitelist);
            return preparedStatement;
        };
        jdbcTemplate.query(userToWhitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    /* End of database checks */

    private class SimpleStringRowMapper implements RowMapper<String> {
        @Override
        public String mapRow(ResultSet resultSet, int i) throws SQLException {
            return resultSet.getString(1);
        }
    }

}