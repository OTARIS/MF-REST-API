package de.nutrisafe.functionrights;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowCountCallbackHandler;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import java.sql.PreparedStatement;

@Lazy
@Component
@DependsOn("jdbcTemplate")
@ComponentScan(basePackages = {"de.nutrisafe"})
public class FunctionRightProvider {

    @Autowired
    JdbcTemplate jdbcTemplate;

    public boolean validateFunction(ServletRequest req) {
        String function = req.getParameter("function");
        if(function != null) {
            try {
                String username = SecurityContextHolder.getContext().getAuthentication().getName();
                if(isFunctionWhitelisted(function, username)) {
                    return true;
                }
            } catch (Exception e) {
                System.err.println("Could not load user details!");
                e.printStackTrace();
            }
        } else
            return true;
        return false;
    }

    private boolean isFunctionWhitelisted(String function, String username) {
        RowCountCallbackHandler countCallback = new RowCountCallbackHandler();
        PreparedStatementCreator whitelistSelectStatement = connection -> {
            PreparedStatement preparedStatement = connection.prepareStatement("select * from " +
                    "function, user_to_whitelist where " +
                    "function.name = ? and " +
                    "function.whitelist = user_to_whitelist.whitelist and " +
                    "user_to_whitelist.username = ?");
            preparedStatement.setString(1, function);
            preparedStatement.setString(2, username);
            return preparedStatement;
        };
        jdbcTemplate.query(whitelistSelectStatement, countCallback);
        return countCallback.getRowCount() > 0;
    }

}