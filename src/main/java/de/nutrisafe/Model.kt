package de.nutrisafe

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.RowMapper
import java.sql.ResultSet

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties
open class Config{var name: String = "unknown"; var company: String = "unknown"; var environment: String = "unknown"
    var defaultNetwork: String = "nutrisafe"; var networkConfigPath: String = "connection.json"
    var databaseConfig: DatabaseConfig = DatabaseConfig()}
open class DatabaseConfig{var username: String = "unknown"; var password: String = "unknown"
    var host: String = "//localhost"; var port: Int = 5432}
data class User(val name: String, val enabled: Boolean)
data class HyperledgerAccount(val name: String, val account: String, val affiliation: String, val mspId: String)
class Model {
    var hyperledgerAccountRowMapper: RowMapper<HyperledgerAccount> = RowMapper<HyperledgerAccount> { resultSet: ResultSet, _: Int ->
        HyperledgerAccount(resultSet.getString("hyperledgername"), resultSet.getString("account"), resultSet.getString("affiliation"), resultSet.getString("mspId"))
    }
    var rolesRowMapper: RowMapper<String> = RowMapper<String> { resultSet: ResultSet, _: Int ->
        resultSet.getString("role")
    }
}