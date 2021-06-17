#!/bin/bash
echo "    Saving application.yml to $1"
cat << EOF > $1
# Member Info
org: DeoniMSP # your member name
cert: /app/config/deoni_admin_cert.pem # your certificate
pk: /app/config/deoni_private_key # your private key

# Network Info
network: /app/config/connection.json # absolute path to your connection.json
channel: trackandtrace # The channel that you want to interact with
chaincode: MF-Chain-Code # the chaincode name

# Database Info
dbName: ${POSTGRES_DB} # the name of your user database
dbDriver: postgresql # the database driver
dbUser: ${POSTGRES_USER} # the name of a privileged database user
dbPassword: ${POSTGRES_PASSWORD} # the pass of this privileged database user
dbHost: db # the host adress of your user database. Use localhost if not using docker-compose to run the mf-rest-api
dbPort: 5432 # the port of your user database
EOF
