#!/bin/sh

export CONFIG_FILE=/nevermined-gateway/config.ini
export KEEPER_PATH=${KEEPER_PATH:-'/usr/local/nevermined-contracts/'}
envsubst < /nevermined-gateway/config.ini.template > /nevermined-gateway/config.ini
if [ "${LOCAL_CONTRACTS}" = "true" ]; then
  echo "Waiting for contracts to be generated..."
  while [ ! -f "/usr/local/nevermined-contracts/ready" ]; do
    sleep 2
  done
fi

/bin/cp -up /usr/local/nevermined-contracts/* /usr/local/artifacts/ 2>/dev/null || true

gunicorn -b ${GATEWAY_URL#*://} -w ${GATEWAY_WORKERS} -t ${GATEWAY_TIMEOUT} nevermined_gateway.run:app
tail -f /dev/null
