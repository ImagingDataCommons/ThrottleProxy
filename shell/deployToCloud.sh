#!/usr/bin/env bash

#
# Script for deployment from the desktop
#

trap 'mv hold_config.txt config.txt; mv hold_app.yaml app.yaml' EXIT

PROJECT=YOUR_PROJECT_NAME_HERE
PROXY_CONFIG_GCS_PATH=gs://YOUR_DEPLOY_BUCKET_NAME_HERE/config.txt
APP_YAML_GCS_PATH=gs://YOUR_DEPLOY_BUCKET_NAME_HERE/app.yaml
PROXY_RUNTIME_SA_NAME=YOUR_PROXY_RUNTIME_SERVICE_ACCOUNT_NAME_HERE
LOAD_FROM_CLOUD="TRUE if you want to get config.txt and app.yaml from cloud bucket, else FALSE"

ENV_FILE="./deployToCloud-SetEnv.sh"

if [ -f "${ENV_FILE}" ]; then
    source "${ENV_FILE}"
fi

cd ..

#
# Always move local copies to hold, always moved back at the end
#
mv config.txt hold_config.txt
mv app.yaml hold_app.yaml
if [ "${LOAD_FROM_CLOUD}" == "TRUE" ] ; then
    gsutil cp "${PROXY_CONFIG_GCS_PATH}" ./config.txt
    gsutil cp "${APP_YAML_GCS_PATH}" ./app.yaml
else
    cp hold_config.txt config.txt
    cp hold_app.yaml app.yaml
fi
#
# Google docs say that if you want App Engine Standard to talk to redis, you are
# using a Serverless VPC access connector, which means that RIGHT NOW (02/2020) you
# MUST use the gcloud beta:
#
gcloud beta app deploy --verbosity=debug ./app.yaml --quiet  --service-account=${PROXY_RUNTIME_SA_NAME} --project=${PROJECT}

