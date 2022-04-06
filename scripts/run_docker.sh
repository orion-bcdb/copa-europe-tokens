# run both orion-server and copa-tokens-server together ina container.

docker network create --driver bridge copa-net

# run the orion-server in a container
docker run -dit --rm --name orion1.net --network copa-net \
    -v $(pwd)/deployment/crypto/:/etc/orion-server/crypto \
    -v $(pwd)/ledger:/var/orion-server/ledger \
    -v $(pwd)/deployment/orion-config-docker:/etc/orion-server/config \
    -p 6001:6001 -p 7050:7050 orionbcdb/orion-server

sleep 15

# run the copa-tokens-server in a container
docker run -dit --rm --name tokens1.net --network copa-net \
    -v $(pwd)/deployment/crypto/:/etc/copa-europe-tokens/crypto \
    -v $(pwd)/deployment/config-docker:/etc/copa-europe-tokens/config \
    -p 6101:6101 orionbcdb/copa-tokens-server

sleep 5

# do curl on the copa-tokens-server
curl http://127.0.0.1:6101/status
echo

curl http://127.0.0.1:6101/tokens/types/xxx
echo

curl http://127.0.0.1:6101/tokens/assets/xxx.yyy
echo

curl http://127.0.0.1:6101/tokens/users/zzz
echo

sleep 5

docker stop orion1.net tokens1.net

docker network rm copa-net