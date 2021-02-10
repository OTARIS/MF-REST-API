package de.nutrisafe;

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
import org.springframework.jdbc.support.MetaDataAccessException;
import org.springframework.jdbc.support.rowset.SqlRowSet;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.sql.*;
import java.util.*;

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

    // Todo: we might want to remove this method due to it's insecure character!
    List<Map<String, Object>> selectFromDatabase(final String[] cols, final String tableName) throws Exception {
        if (cols.length < 1)
            throw new Exception("No column defined.");

        // check if table name exists
        Set<String> tableNames = JdbcUtils.extractDatabaseMetaData(Objects.requireNonNull(this.jdbcTemplate.getDataSource()), new GetTableNames());
        if(!tableNames.contains(tableName))
            throw new Exception("Table name does not exist.");

        // check if the columns exist
        SqlRowSet oneRowFromTheTable = jdbcTemplate.queryForRowSet("select * from " + tableName + " limit 1");
        for(String col : cols)
            oneRowFromTheTable.findColumn(col);

        StringBuilder selectStatementBuilder = new StringBuilder("select ");
        selectStatementBuilder.append(cols[0]);
        for(int i = 1; i < cols.length; i++) {
            selectStatementBuilder.append(", ");
            selectStatementBuilder.append(cols[i]);
        }
        selectStatementBuilder.append(" from ");
        selectStatementBuilder.append(tableName);
        return jdbcTemplate.queryForList(selectStatementBuilder.toString());
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
            try {
                preparedStatement.setString(1, whitelist);
            } catch (Throwable t) {
                try (preparedStatement) {
                    throw t;
                }
            }
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