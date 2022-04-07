# run both orion-server and copa-tokens-server together ina container.

function networkUp() {
  echo "=========================================="
  echo "* Creating a copa-net network"
  echo "=========================================="
  docker network create --driver bridge copa-net

  echo "=========================================="
  echo "* Starting the Orion server"
  echo "=========================================="

  # run the orion-server in a container
  docker run -dit --rm --name orion1.net --network copa-net \
    -v $(pwd)/deployment/crypto/:/etc/orion-server/crypto \
    -v $(pwd)/ledger:/var/orion-server/ledger \
    -v $(pwd)/deployment/orion-config-docker:/etc/orion-server/config \
    -p 6001:6001 -p 7050:7050 orionbcdb/orion-server

  sleep 15

  echo "=========================================="
  echo "* Starting the COPA tokens server"
  echo "=========================================="

  # run the copa-tokens-server in a container
  docker run -dit --rm --name tokens1.net --network copa-net \
    -v $(pwd)/deployment/crypto/:/etc/copa-europe-tokens/crypto \
    -v $(pwd)/deployment/config-docker:/etc/copa-europe-tokens/config \
    -p 6101:6101 orionbcdb/copa-tokens-server

  sleep 5

  echo "=========================================="
  echo "* Containers are up"
  echo "=========================================="
}

function networkDown() {
  echo "=========================================="
  echo "* Stopping Containers"
  echo "=========================================="

  docker stop orion1.net tokens1.net
  docker network rm copa-net
}


function doCurl() {
  echo "=========================================="
  echo "* Executing cUrl commands:"
  echo "=========================================="

  echo "=========================================="
  echo "* GET /status"
  echo "=========================================="

  curl http://127.0.0.1:6101/status
  echo

  echo "=========================================="
  echo "* Deploy a token type"
  echo "=========================================="

  curl -X POST http://127.0.0.1:6101/tokens/types \
       -H 'Content-Type: application/json' \
       -d '{"name":"my NFT","description":"my NFT description"}'
  echo

  echo "=========================================="
  echo "* Get a token type"
  echo "==========================================\n"

  curl http://127.0.0.1:6101/tokens/types/VZ-S5ASzbzZII2Z7b4Xh_A
  echo

  echo "=========================================="
  echo "* Add user 'bob'"
  echo "==========================================\n"

  curl -X POST http://127.0.0.1:6101/tokens/users \
       -H 'Content-Type: application/json' \
       -d '{"identity":"bob","certificate":"MIIBUjCB+QIUS4a6hyrE6cp4oRdzEdBwAmUUCWEwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCSUwxDjAMBgNVBAgMBUhhaWZhMQ0wCwYDVQQKDARCQ0RCMB4XDTIyMDQwNjE4MTQwOVoXDTIzMDQwNjE4MTQwOVowLDELMAkGA1UEBhMCSUwxDjAMBgNVBAgMBUhhaWZhMQ0wCwYDVQQKDARCQ0RCMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+CgdUE4a8FvNiJQ17Aa91FKza8JznniSqSBtZ3S+cR5U+MJYntppKWdDj1SFvpjjBW159n9fdls3l3bNuZ//jDAKBggqhkjOPQQDAgNIADBFAiBUE42xLwZ4P7HgYiWeiRFPMrEAnWEOliU+pWJQ5ywPfwIhAIe2P+ote6zfYU7SJDwIAnjIaUI3oSy2x3zuZil3Kdle","privilege":[]}'
  echo

  echo "=========================================="
  echo "* Get user 'bob'"
  echo "==========================================\n"

  curl http://127.0.0.1:6101/tokens/users/bob
  echo

  echo "=========================================="
  echo "* Prepare mint"
  echo "==========================================\n"

  curl -X POST http://127.0.0.1:6101/tokens/assets/prepare-mint/VZ-S5ASzbzZII2Z7b4Xh_A \
         -H 'Content-Type: application/json' \
         -d '{"owner":"bob","assetData":"bob token 1","assetMetadata":"token details"}'
  echo

  echo "=========================================="
  echo "* Submit Prepare mint"
  echo "==========================================\n"

  curl -X POST http://127.0.0.1:6101/tokens/assets/submit \
         -H 'Content-Type: application/json' \
         -d '{"tokenId":"VZ-S5ASzbzZII2Z7b4Xh_A.jaoa1ufiluatma9-ncjjOQ","txEnvelope":"CqECCgljdXN0b2RpYW4KA2JvYhIsbTQyVmd6cGM5MWRGbTdZUDhnamZRY2p6NFgzZlJ0NVRmQ1hBSXl2ZHdGND0a4AEaG3R0aWQuVlotUzVBU3pielpJSTJaN2I0WGhfQSIYChZqYW9hMXVmaWx1YXRtYTktbmNqak9RKqYBChZqYW9hMXVmaWx1YXRtYTktbmNqak9REnB7ImFzc2V0RGF0YUlkIjoiamFvYTF1ZmlsdWF0bWE5LW5jampPUSIsIm93bmVyIjoiYm9iIiwiYXNzZXREYXRhIjoiYm9iIHRva2VuIDEiLCJhc3NldE1ldGFkYXRhIjoidG9rZW4gZGV0YWlscyJ9GhoSDQoJY3VzdG9kaWFuEAESBwoDYm9iEAEYARJVCgljdXN0b2RpYW4SSDBGAiEAhiEPMiRquwECnf2OtmvVQrMwAym8zq4dZfFK/rb5huUCIQDBg11PZALyv/Q/t3ySfoxIk2Hj9K9nlRw/+3uyBzNJ8w==","txPayloadHash":"Bm0ztRrup1TpAgeQma7Q4X8QlRWBPvfldb9LnCbuHv0=","signer":"bob","signature":"badsigbadsig"}'
  echo
  echo
}

## Parse mode
if [[ $# -lt 1 ]] ; then
  MODE="all"
else
  MODE=$1
fi

# Determine mode of operation and printing out what we asked for
if [ "$MODE" == "up" ]; then
  networkUp
elif [ "$MODE" == "down" ]; then
  networkDown
elif [ "$MODE" == "curl" ]; then
  doCurl
elif [ "$MODE" == "all" ]; then
  networkUp
  doCurl
  networkDown
else
  echo "Invalid parameters"
  exit 1
fi
