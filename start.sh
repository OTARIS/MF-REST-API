#!/bin/bash
cat <<"EOF"
--------------------------------------------------------------------------------
.-.   .-..----..---.  .--.  .-. .-..-.      .----..--.  .----. .----. .-. .---.
|  `.'  || {_ {_   _}/ {} \ | {_} || |      | {_ / {} \ | {}  }| {}  }| |/  ___)
| |\ /| || {__  | | /  /\  \| { } || `--.   | | /  /\  \| {}  }| .-. \| |\     )
`-' ` `-'`----' `-' `-'  `-'`-' `-'`----'   `-' `-'  `-'`----' `-' `-'`-' `---'
-- REST API --------------------------------------------------------------------

>> https://github.com/otaris/MF-REST-API

EOF

if [ "$EUID" -ne 0 ]
  then echo "[-] MetaHL Fabric setup needs to be run as root"
  exit
fi

while read LINE
  do export $LINE
done < mf.env

export MF_HOST=$(ip addr show | grep docker | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | awk -F'inet ' '{ print $2 }')

echo "[+] Hyperledger Fabric Host is set to ${MF_HOST}"

echo "[+] Generating configs"
./config/scripts/generate_application-yml.sh $PWD/config/application.yml
./config/scripts/generate_connection-json.sh $PWD/config/connection.json

echo "[+] Starting docker-compose"
sudo docker-compose up --build
