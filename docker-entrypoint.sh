#!/bin/sh

export CONFIG_FILE=/nevermind-gateway/config.ini
envsubst < /nevermind-gateway/config.ini.template > /nevermind-gateway/config.ini
if [ "${LOCAL_CONTRACTS}" = "true" ]; then
  echo "Waiting for contracts to be generated..."
  while [ ! -f "/usr/local/nevermind-contracts/ready" ]; do
    sleep 2
  done
fi

/bin/cp -up /usr/local/nevermind-contracts/* /usr/local/artifacts/ 2>/dev/null || true

gunicorn -b ${GATEWAY_URL#*://} -w ${GATEWAY_WORKERS} -t ${GATEWAY_TIMEOUT} nevermind_gateway.run:app
tail -f /dev/null
