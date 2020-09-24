package de.nutrisafe

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties
open class Config{var name: String = "unknown"; var company: String = "unknown"; var environment: String = "unknown"
    var defaultNetwork: String = "nutrisafe"; var networkConfigPath: String = "connection.json"; var chaincodeName: String = "nutrisafe-chaincode"
    var channelName: String = "cheese"; var certPath: String = "unknown"; var privateKeyPath: String = "unknown"
    var databaseConfig: DatabaseConfig = DatabaseConfig()}
open class DatabaseConfig{var username: String = "unknown"; var password: String = "unknown"
    var host: String = "//localhost"; var port: Int = 5432}