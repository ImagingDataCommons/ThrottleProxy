#!/usr/bin/env bash


trap 'rm ./privatekey.json; mv hold_config.txt config.txt' EXIT

source ./setEnvVars.sh
cd ..
mv config.txt hold_config.txt
gsutil cp "${PROXY_CONFIG_GCS_PATH}" ./config.txt
gsutil cp "${PROXY_SA_KEY_GCS_PATH}" ./privatekey.json

GOT_IT=`grep ${PROXY_SERVICE_NAME} app.yaml`

if [ -z "${GOT_IT}" ]; then
  cp app.yaml app.yaml.orig
  cat app.yaml.orig | sed 's/ghc-proxy/'${PROXY_SERVICE_NAME}'/' > app.yaml
fi

#
# Google docs say that if you want App Engine Standard to talk to redis, you are
# using a Serverless VPC access connector, which means that RIGHT NOW (02/2020) you
# MUST use the gclould beta:
#
gcloud beta app deploy --verbosity=debug ./app.yaml --quiet --project=${PROJECT}

if [ -z "${GOT_IT}" ]; then
  mv app.yaml.orig app.yaml
fi
