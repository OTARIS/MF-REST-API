package de.metahlfabric;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowCountCallbackHandler;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.DatabaseMetaDataCallback;
import org.springframework.jdbc.support.JdbcUtils;
import org.springframework.jdbc.support.rowset.SqlRowSet;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.*;

/**
 * This class handles common calls on the user database and wraps them in easier functions.
 *
 * @author Dennis Lamken, Kathrin Kleinhammer
 *
 * Copyright 2021 OTARIS Interactive Services GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@Lazy
@Service
@SuppressFBWarnings("OBL_UNSATISFIED_OBLIGATION_EXCEPTION_EDGE")
public class PersistenceManager {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public UserDetails getCurrentUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            return (UserDetails) principal;
        } else
            return null;
    }

    public List<String> getAuthorities(String username) {
        List<GrantedAuthority> authorityObjectList = new LinkedList<>(userDetailsService.loadUserByUsername(username).getAuthorities());
        List<String> result = new ArrayList<>();
        for (GrantedAuthority authority : authorityObjectList) {
            result.add(authority.getAuthority());
        }
        return result;
    }

    /* Database helper functions */

    public String getUsernameOfExternalUser(final String extUsername) {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select username from external_users where extusername = ?");
            preparedStatement.setString(1, extUsername);
            return preparedStatement;
        };
        List<String> usernames = this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
        return usernames.size() > 0 ? usernames.get(0) : null;
    }

    public String getExternalUsernameOfUser(final String username) {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select extusername from external_users where username = ?");
            preparedStatement.setString(1, username);
            return preparedStatement;
        };
        List<String> usernames = this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
        return usernames.size() > 0 ? usernames.get(0) : null;
    }

    List<String> selectAllUsers() {
        return this.jdbcTemplate.queryForList("select username from users", String.class);
    }

    List<String> selectUsersByAuthority(final String role) {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select username from authorities where authority = ?");
            preparedStatement.setString(1, role);
            return preparedStatement;
        };
        return this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
    }

    List<String> selectFromDatabase(PreparedStatementCreator selectStatement) {
        return this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
    }

    List<String> selectUserToWhitelistEntriesOfUser(final String username) {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select whitelist from user_to_whitelist where username = ?");
            preparedStatement.setString(1, username);
            return preparedStatement;
        };
        return this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
    }

    List<String> selectFunctionToWhitelistEntriesOfWhitelist(final String whitelist) {
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select name from function where whitelist = ?");
            preparedStatement.setString(1, whitelist);
            return preparedStatement;
        };
        return this.jdbcTemplate.query(selectStatement, new SimpleStringRowMapper());
    }

    List<String> selectAllFunctions() {
        return this.jdbcTemplate.queryForList("select name from function", String.class);
    }

    List<String> selectAllWhitelists() {
        return this.jdbcTemplate.queryForList("select name from whitelist", String.class);
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

    void insertExternalUser(final String username, final String extUsername) {
        PreparedStatementCreator externalUserInsertStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("insert into " +
                    "external_users(username, extusername, token, valid_until) " +
                    "values (?, ?, ?, ?)");
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, extUsername);
            preparedStatement.setString(3, "");
            preparedStatement.setTimestamp(4, new Timestamp(0L));
            return preparedStatement;
        };
        jdbcTemplate.update(externalUserInsertStatement);
    }

    public void updateTokenOfExternalUser(final String extUsername, final String token, final long validUntil) {
        PreparedStatementCreator externalUserInsertStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("update " +
                    "external_users set token = ?, valid_until = ? " +
                    "where extusername = ?");
            preparedStatement.setString(1, token);
            preparedStatement.setTimestamp(2, new Timestamp(validUntil));
            preparedStatement.setString(3, extUsername);
            return preparedStatement;
        };
        jdbcTemplate.update(externalUserInsertStatement);
    }

    public boolean isTokenValid(final String token) {
        PreparedStatementCreator validitySelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select valid_until " +
                    "from external_users " +
                    "where token = ?");
            preparedStatement.setString(1, token);
            return preparedStatement;
        };
        List<Long> times = this.jdbcTemplate.query(validitySelectStatement, new SimpleTimestampRowMapper());
        return times.size() > 0 && times.get(0) > System.currentTimeMillis();
    }

    public String getExtUsername(final String token) {
        PreparedStatementCreator tokenSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select extusername " +
                    "from external_users " +
                    "where token = ?");
            preparedStatement.setString(1, token);
            return preparedStatement;
        };
        List<String> extUsernames = this.jdbcTemplate.query(tokenSelectStatement, new SimpleStringRowMapper());
        return extUsernames.size() > 0 ? extUsernames.get(0) : null;
    }

    void deleteExternalUserOfUser(final String username) {
        PreparedStatementCreator externalUserDeleteStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("delete from external_users where username = ?");
            preparedStatement.setString(1, username);
            return preparedStatement;
        };
        jdbcTemplate.update(externalUserDeleteStatement);
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

    boolean isOAuthUser(String username) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator externalUsersSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from external_users " +
                    "where username = ?");
            preparedStatement.setString(1, username);
            return preparedStatement;
        };
        jdbcTemplate.query(externalUsersSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    boolean IsExternalUsernameUsed(final String extUsername) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator selectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from external_users where extusername = ?");
            preparedStatement.setString(1, extUsername);
            return preparedStatement;
        };
        this.jdbcTemplate.query(selectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

    /* End of database checks */

    public String getSHA256Hashed(String string) throws NoSuchAlgorithmException {
        byte[] hashedBytes = MessageDigest.getInstance("SHA-256").digest(string.getBytes(StandardCharsets.UTF_8));
        StringBuilder hashedStringBuilder = new StringBuilder(2 * hashedBytes.length);
        for (byte hash : hashedBytes) {
            String hex = Integer.toHexString(0xff & hash);
            if(hex.length() == 1)
                hashedStringBuilder.append('0');
            hashedStringBuilder.append(hex);
        }
        return hashedStringBuilder.toString();
    }

    private static class SimpleStringRowMapper implements RowMapper<String> {
        @Override
        public String mapRow(ResultSet resultSet, int i) throws SQLException {
            return resultSet.getString(1);
        }
    }

    private static class SimpleTimestampRowMapper implements RowMapper<Long> {
        @Override
        public Long mapRow(ResultSet resultSet, int i) throws SQLException {
            return resultSet.getTimestamp(1).getTime();
        }
    }

    private static class GetTableNames implements DatabaseMetaDataCallback<Set<String>> {

        @NotNull
        public Set<String> processMetaData(DatabaseMetaData dbmd) throws SQLException {
            ResultSet rs = dbmd.getTables(dbmd.getUserName(), null, null, new String[]{"TABLE"});
            Set<String> l = new HashSet<>();
            while (rs.next()) {
                l.add(rs.getString(3));
            }
            return l;
        }
    }

}