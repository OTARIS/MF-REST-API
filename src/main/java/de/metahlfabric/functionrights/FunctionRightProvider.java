package de.metahlfabric.functionrights;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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

/**
 * The FunctionRightProvider validates if a {@link javax.servlet.ServletRequest} is allowed by the current user based
 * on the configured whitelists.
 *
 * You can check this by calling {@link #validateFunction(ServletRequest)}.
 *
 * @author Dennis Lamken
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
@Component
@DependsOn("jdbcTemplate")
@ComponentScan(basePackages = {"de.metahlfabric"})
@SuppressFBWarnings("OBL_UNSATISFIED_OBLIGATION_EXCEPTION_EDGE")
public class FunctionRightProvider {

    @Autowired
    JdbcTemplate jdbcTemplate;

    /**
     * Validates if a {@link javax.servlet.ServletRequest} is allowed by the current user based on the configured
     * whitelists.
     *
     * @param req the request that needs to be checked
     * @return true if the function call is allowed or if no function parameter is given, else false
     */
    public boolean validateFunction(ServletRequest req) {
        String function = req.getParameter("function");
        if (function != null) {
            try {
                String username = SecurityContextHolder.getContext().getAuthentication().getName();
                if (isFunctionWhitelisted(function, username)) {
                    return true;
                }
            } catch (Exception e) {
                System.err.println("[MF] Could not load user details!");
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