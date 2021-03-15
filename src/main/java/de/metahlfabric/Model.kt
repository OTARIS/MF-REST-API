package de.metahlfabric

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component

@Component
@Configuration
@EnableConfigurationProperties
@ConfigurationProperties
open class HyperledgerConfig {
    var org: String = "unknown"
    var cert: String = "unknown"
    var pk: String = "unknown"
    var network: String = "connection.json"
    var channel: String = "cheese"
    var chaincode: String = "nutrisafe-chaincode"
}

@Component
@Configuration
@EnableConfigurationProperties
@ConfigurationProperties
open class DatabaseConfig {
    var dbName: String = "unknown"
    var dbDriver: String = "postgresql"
    var dbUser: String = "unknown"
    var dbPassword: String = "unknown"
    var dbHost: String = "//localhost"
    var dbPort: Int = 5432
}