#!/bin/bash
echo "    Saving connection.json to $1"
cat << EOF > $1
{
  "name": "basic-network",
  "version": "1.0.0",
  "client": {
    "organization": "Deoni",
    "connection": {
      "timeout": {
        "peer": {
          "endorser": "300"
        },
        "orderer": "300"
      }
    }
  },
  "channels": {
    "trackandtrace": {
      "orderers": [
        "orderer.unibw.de"
      ],
      "peers": {
        "peer0.deoni.de": {
          "endorsingPeer": true,
          "chaincodeQuery": true,
          "ledgerQuery": true,
          "eventSource": true
        }
      }
    }
  },
  "organizations": {
    "Deoni": {
      "mspid": "DeoniMSP",
      "peers": [
        "peer0.deoni.de"
      ]
    }
  },
  "orderers": {
    "orderer.unibw.de": {
      "url": "grpcs://${MF_HOST}:7050",
      "grpcOptions": {
        "ssl-target-name-override": "orderer.unibw.de",
        "hostnameOverride": "orderer.unibw.de"
      },
      "tlsCACerts": {
        "path": "/app/config/orderer_tlsca_cert.crt"
      }
    }
  },
  "peers": {
    "peer0.deoni.de": {
      "url": "grpcs://${MF_HOST}:7051",
      "grpcOptions": {
        "ssl-target-name-override": "peer0.deoni.de",
        "hostnameOverride": "peer0.deoni.de"
      },
      "tlsCACerts": {
        "path": "/app/config/deoni_tlsca_cert.crt"
      }
    }
  }

}
EOF
