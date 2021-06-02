package de.metahlfabric

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component

/**
 * This class represents the loaded Hyperledger configuration for interaction with the blockchain.
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

/**
 * This class represents the loaded user database configuration of the REST API.
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