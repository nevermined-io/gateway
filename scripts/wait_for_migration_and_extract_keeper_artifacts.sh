#!/bin/bash

RETRY_COUNT=0
COMMAND_STATUS=1

mkdir -p artifacts

NEVERMIND_CONTRACTS_DOCKER_ID=$(docker container ls | grep nevermind-contracts | awk '{print $1}')

until [ $COMMAND_STATUS -eq 0 ] || [ $RETRY_COUNT -eq 120 ]; do
  docker cp $NEVERMIND_CONTRACTS_DOCKER_ID:/nevermind-contracts/artifacts/ready ./artifacts/
  COMMAND_STATUS=$?
  sleep 5
  let RETRY_COUNT=RETRY_COUNT+1
  NEVERMIND_CONTRACTS_DOCKER_ID=$(docker container ls | grep nevermind-contracts | awk '{print $1}')
done

if [ $COMMAND_STATUS -ne 0 ]; then
  echo "Waited for more than two minutes, but keeper contracts have not been migrated yet. Did you run an Ethereum RPC client and the migration script?"
  exit 1
fi

docker cp $NEVERMIND_CONTRACTS_DOCKER_ID:/nevermind-contracts/artifacts/. ./artifacts/
sleep 20

