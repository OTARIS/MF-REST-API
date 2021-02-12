package de.nutrisafe

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties
open class Config {
    var company: String = "unknown"
    var networkConfigPath: String = "connection.json"
    var chaincodeName: String = "nutrisafe-chaincode"
    var channelName: String = "cheese"
    var certPath: String = "unknown"
    var privateKeyPath: String = "unknown"
    var databaseConfig: DatabaseConfig = DatabaseConfig()
}

open class DatabaseConfig {
    var name: String = "unknown"
    var driver: String = "postgresql"
    var username: String = "unknown"
    var password: String = "unknown"
    var host: String = "//localhost"
    var port: Int = 5432
}